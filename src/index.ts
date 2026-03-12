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

// Internal ALB URL
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

// ── Role enrichment ──────────────────────────────────────────────────────────
// Downstream data-plane services cannot query the User table (different DB
// credentials). The BFF resolves the user's role by calling auth-service and
// forwards it via the trusted `x-lb-enriched-role` header so that the
// requireAuth middleware in each service picks it up at priority 1.

interface RoleCacheEntry {
  role: string;
  expiresAt: number;
}

const roleCache = new Map<string, RoleCacheEntry>();
const ROLE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Periodic cleanup of expired entries (every 60s)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of roleCache) {
    if (entry.expiresAt <= now) roleCache.delete(key);
  }
}, 60_000).unref();

/**
 * Middleware: resolve user role via auth-service and attach to request.
 * Runs before proxy routes for non-auth paths.
 * On failure, silently continues — downstream services fall back to their
 * own role resolution (DB lookup or TENANT default).
 */
app.use(async (req, _res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return next();

  // Skip for auth routes — auth-service resolves its own roles
  if (req.path.startsWith('/api/auth')) return next();

  try {
    // Decode JWT payload (no verification — downstream services verify)
    const token = auth.slice(7);
    const parts = token.split('.');
    if (parts.length !== 3) return next();

    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString(),
    );
    const sub = payload.sub as string | undefined;
    if (!sub) return next();

    // Check cache
    const cached = roleCache.get(sub);
    if (cached && cached.expiresAt > Date.now()) {
      (req as any)._enrichedRole = cached.role;
      return next();
    }

    // Call auth-service to resolve the role
    const authTarget = getTarget('auth');
    const meUrl = `${authTarget}/internal/auth/me`;
    const resp = await fetch(meUrl, {
      headers: { Authorization: auth },
      signal: AbortSignal.timeout(3000), // 3s timeout
    });

    if (resp.ok) {
      const data = (await resp.json()) as { role?: string };
      if (data.role) {
        roleCache.set(sub, {
          role: data.role,
          expiresAt: Date.now() + ROLE_CACHE_TTL_MS,
        });
        (req as any)._enrichedRole = data.role;
        logger.debug(
          { sub, role: data.role },
          'BFF role enrichment: resolved via auth-service',
        );
      }
    } else {
      logger.warn(
        { sub, status: resp.status },
        'BFF role enrichment: auth-service returned non-OK',
      );
    }
  } catch (err) {
    logger.warn({ err }, 'BFF role enrichment failed — downstream will resolve role');
  }

  next();
});

// ── Proxy helpers ────────────────────────────────────────────────────────────

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
        // Forward enriched role (set by role-enrichment middleware above)
        const enrichedRole = (req as any)._enrichedRole as string | undefined;
        if (enrichedRole) {
          proxyReq.setHeader('x-lb-enriched-role', enrichedRole);
        }
        // Forward dev bypass headers (only in non-production; stripped by middleware otherwise)
        if (!IS_PRODUCTION) {
          for (const h of DEV_BYPASS_HEADERS) {
            const val = req.headers[h];
            if (val) proxyReq.setHeader(h, val as string);
          }
        }
        // Re-stream the body
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
      // The raw body is already available because express.json() already consumed
      // it and we need to re-stream it from req (the original readable stream
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
createProxy('properties', '/api/properties', '/internal/properties');
createProxy('leases', '/api/leases', '/internal/leases');
// Tenant invitation accept routes — public, no auth required.
// Mounted before the general /api/tenants proxy for specificity.
createProxy('tenants', '/api/tenants/invitations/accept', '/internal/tenants/invitations/accept');
createProxy('tenants', '/api/tenants', '/internal/tenants');
createProxy('maintenance', '/api/maintenance', '/internal/maintenance');
createProxy('payments', '/api/payments', '/internal/payments');
createProxy('notifications', '/api/notifications', '/internal/notifications');
createProxy('documents', '/api/documents', '/internal/documents');
createProxy('reports', '/api/reports', '/internal/reports');

startApp(app);
