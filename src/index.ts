import { createApp, startApp, logger } from '@leasebase/service-common';
import { createProxyMiddleware, fixRequestBody, type Options } from 'http-proxy-middleware';

const app = createApp();

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Fail fast: DEV_AUTH_BYPASS must never be enabled in production
if (IS_PRODUCTION && process.env.DEV_AUTH_BYPASS === 'true') {
  logger.fatal('DEV_AUTH_BYPASS=true is not allowed when NODE_ENV=production — aborting');
  process.exit(1);
}

if (!IS_PRODUCTION && process.env.DEV_AUTH_BYPASS === 'true') {
  logger.warn('⚠ DEV_AUTH_BYPASS is enabled — auth bypass headers will be forwarded. Do NOT use in production.');
}

// Dev bypass header names
const DEV_BYPASS_HEADERS = ['x-dev-user-email', 'x-dev-user-role', 'x-dev-org-id'];

// Strip dev bypass headers in production/non-dev environments
if (IS_PRODUCTION) {
  app.use((req, _res, next) => {
    for (const h of DEV_BYPASS_HEADERS) {
      delete req.headers[h];
    }
    next();
  });
}

// Internal ALB URL — in ECS, services communicate via the ALB.
// For local dev, each service runs on a different port.
const ALB_URL = process.env.INTERNAL_ALB_URL || 'http://localhost';

// Service port mapping for local development
const SERVICE_PORTS: Record<string, number> = {
  auth: Number(process.env.AUTH_SERVICE_PORT) || 3001,
  properties: Number(process.env.PROPERTY_SERVICE_PORT) || 3002,
  leases: Number(process.env.LEASE_SERVICE_PORT) || 3003,
  tenants: Number(process.env.TENANT_SERVICE_PORT) || 3004,
  maintenance: Number(process.env.MAINTENANCE_SERVICE_PORT) || 3005,
  payments: Number(process.env.PAYMENT_SERVICE_PORT) || 3006,
  notifications: Number(process.env.NOTIFICATION_SERVICE_PORT) || 3007,
  documents: Number(process.env.DOCUMENT_SERVICE_PORT) || 3008,
  reports: Number(process.env.REPORTING_SERVICE_PORT) || 3009,
};

function getTarget(service: string): string {
  // In deployed mode, all services are behind the same ALB with path-based routing
  if (process.env.NODE_ENV === 'production' || process.env.USE_ALB === 'true') {
    return ALB_URL;
  }
  // In local dev, each service runs on its own port
  const port = SERVICE_PORTS[service] || 3001;
  return `http://localhost:${port}`;
}

function createProxy(service: string, pathPrefix: string, targetPathPrefix: string): void {
  const proxyOptions: Options = {
    target: getTarget(service),
    changeOrigin: true,
    // Express strips the mount path (pathPrefix) from req.url before the
    // proxy middleware sees it, so we rewrite the remaining relative path
    // by prepending the target prefix.
    pathRewrite: { '^/': `${targetPathPrefix}/` },
    on: {
      proxyReq: (proxyReq, req) => {
        // Forward correlation ID
        const correlationId = (req as any).correlationId;
        if (correlationId) {
          proxyReq.setHeader('x-correlation-id', correlationId);
        }
        // Forward auth headers
        const auth = req.headers.authorization;
        if (auth) {
          proxyReq.setHeader('Authorization', auth);
        }
        // Forward dev bypass headers (only in non-production; stripped by middleware otherwise)
        if (!IS_PRODUCTION) {
          for (const h of DEV_BYPASS_HEADERS) {
            const val = req.headers[h];
            if (val) proxyReq.setHeader(h, val as string);
          }
        }
        // Re-stream the body that express.json() already consumed.
        // MUST be called after all setHeader() calls, since it writes
        // the body which flushes the headers.
        fixRequestBody(proxyReq, req);
      },
      error: (err, _req, res) => {
        logger.error({ err, service }, `Proxy error for ${service}`);
        if ('writeHead' in res && typeof res.writeHead === 'function') {
          (res as any).writeHead(502);
          (res as any).end(JSON.stringify({
            error: { code: 'BAD_GATEWAY', message: `Service ${service} is unavailable` },
          }));
        }
      },
    },
  };

  app.use(pathPrefix, createProxyMiddleware(proxyOptions));
  logger.info({ service, pathPrefix, targetPathPrefix }, `Proxy route registered`);
}

// ── Stripe webhook proxy (raw body passthrough) ─────────────────────────────
// Webhook paths must forward the raw body intact for Stripe signature verification.
// The standard proxy uses fixRequestBody which re-serializes parsed JSON — that
// breaks signature verification. This dedicated proxy streams the raw body.
const webhookProxy = createProxyMiddleware({
  target: getTarget('payments'),
  changeOrigin: true,
  pathRewrite: { '^/': '/internal/payments/' },
  on: {
    proxyReq: (proxyReq, req) => {
      const correlationId = (req as any).correlationId;
      if (correlationId) proxyReq.setHeader('x-correlation-id', correlationId);
      // Forward stripe-signature header (critical for verification)
      const sig = req.headers['stripe-signature'];
      if (sig) proxyReq.setHeader('stripe-signature', sig as string);
      // Do NOT call fixRequestBody — let the raw body stream through.
      // The raw body is already available because express.json() stored it
      // and we need to re-stream it from req (the original readable stream
      // is consumed by express.json). We write the raw buffer directly.
      if (req.body && Buffer.isBuffer(req.body)) {
        proxyReq.setHeader('Content-Length', req.body.length.toString());
        proxyReq.write(req.body);
        proxyReq.end();
      } else if (req.body) {
        // Fallback: re-serialize (may break signature, but prevents hang)
        const bodyStr = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyStr).toString());
        proxyReq.write(bodyStr);
        proxyReq.end();
      }
    },
    error: (err, _req, res) => {
      logger.error({ err }, 'Webhook proxy error');
      if ('writeHead' in res && typeof res.writeHead === 'function') {
        (res as any).writeHead(502);
        (res as any).end(JSON.stringify({
          error: { code: 'BAD_GATEWAY', message: 'Payments webhook service unavailable' },
        }));
      }
    },
  },
});

// Mount webhook proxy BEFORE the general payments proxy (more specific first)
app.use('/api/payments/webhooks', webhookProxy);
logger.info('Webhook proxy route registered: /api/payments/webhooks → payments-service');

// Register proxy routes (order matters — more specific first)
createProxy('auth', '/api/auth', '/internal/auth');
createProxy('properties', '/api/pm', '/internal/pm');
createProxy('properties', '/api/properties', '/internal/properties');
createProxy('leases', '/api/leases', '/internal/leases');
createProxy('tenants', '/api/tenants', '/internal/tenants');
createProxy('maintenance', '/api/maintenance', '/internal/maintenance');
createProxy('payments', '/api/payments', '/internal/payments');
createProxy('notifications', '/api/notifications', '/internal/notifications');
createProxy('documents', '/api/documents', '/internal/documents');
createProxy('reports', '/api/reports', '/internal/reports');

startApp(app);
