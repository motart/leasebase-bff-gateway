import { createApp, startApp, logger, queryOne } from '@leasebase/service-common';
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

// ── BFF role enrichment ─────────────────────────────────────────────────────
// Internal header used to forward DB-backed role to downstream microservices.
// MUST be stripped from incoming requests to prevent external injection.
const ENRICHED_ROLE_HEADER = 'x-lb-enriched-role';

/**
 * Decode a JWT payload without signature verification.
 * Safe here because downstream microservices still perform full JWT verification.
 * If the JWT is invalid, downstream will reject the request and the enriched
 * header becomes irrelevant.
 */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

/**
 * Role enrichment middleware.
 *
 * For authenticated (Bearer) requests:
 *   1. Decodes the JWT to extract `sub` (Cognito subject)
 *   2. Looks up the user in the DB by `cognitoSub`
 *   3. If found, sets `x-lb-enriched-role` header with the DB-backed role
 *
 * Skipped for dev-bypass requests (role comes from dev headers).
 * On any failure (decode error, DB unavailable), the request proceeds
 * without enrichment — downstream uses the JWT-derived role (graceful degradation).
 */
async function enrichRole(req: import('express').Request, _res: import('express').Response, next: import('express').NextFunction): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    // Skip enrichment for dev-bypass requests (role already set via headers)
    if (process.env.DEV_AUTH_BYPASS === 'true' && req.headers['x-dev-user-email']) {
      return next();
    }

    const token = authHeader.slice(7);
    const payload = decodeJwtPayload(token);
    if (!payload || !payload.sub) {
      return next();
    }

    const user = await queryOne<{ role: string }>(
      'SELECT "role" FROM "User" WHERE "cognitoSub" = $1',
      [payload.sub],
    );

    if (user) {
      req.headers[ENRICHED_ROLE_HEADER] = user.role;
      logger.debug({ sub: payload.sub, enrichedRole: user.role }, 'Role enriched from DB');
    } else {
      logger.debug({ sub: payload.sub }, 'No DB user found for cognitoSub — skipping role enrichment');
    }
  } catch (err) {
    // Enrichment is best-effort; downstream auth still works without it.
    logger.warn({ err }, 'Role enrichment failed — proceeding without enrichment');
  }
  next();
}

// Strip enriched role header from ALL incoming requests (security: prevent external injection)
app.use((req, _res, next) => {
  delete req.headers[ENRICHED_ROLE_HEADER];
  next();
});

// Strip dev bypass headers in production/non-dev environments
if (IS_PRODUCTION) {
  app.use((req, _res, next) => {
    for (const h of DEV_BYPASS_HEADERS) {
      delete req.headers[h];
    }
    next();
  });
}

// Enrich authenticated requests with DB-backed role
app.use(enrichRole);

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
        // Forward BFF-enriched role header (set by enrichRole middleware)
        const enrichedRole = req.headers[ENRICHED_ROLE_HEADER];
        if (enrichedRole) {
          proxyReq.setHeader(ENRICHED_ROLE_HEADER, enrichedRole as string);
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
      const body = (req as any).body;
      if (body && Buffer.isBuffer(body)) {
        proxyReq.setHeader('Content-Length', body.length.toString());
        proxyReq.write(body);
        proxyReq.end();
      } else if (body) {
        // Fallback: re-serialize (may break signature, but prevents hang)
        const bodyStr = JSON.stringify(body);
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
