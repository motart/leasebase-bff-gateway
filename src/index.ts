import { createApp, startApp, logger } from '@leasebase/service-common';
import { createProxyMiddleware, type Options } from 'http-proxy-middleware';

const app = createApp();

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
        // Forward dev bypass headers
        for (const h of ['x-dev-user-email', 'x-dev-user-role', 'x-dev-org-id']) {
          const val = req.headers[h];
          if (val) proxyReq.setHeader(h, val as string);
        }
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

// Register proxy routes (order matters — more specific first)
createProxy('auth', '/api/auth', '/internal/auth');
createProxy('properties', '/api/properties', '/internal/properties');
createProxy('leases', '/api/leases', '/internal/leases');
createProxy('tenants', '/api/tenants', '/internal/tenants');
createProxy('maintenance', '/api/maintenance', '/internal/maintenance');
createProxy('payments', '/api/payments', '/internal/payments');
createProxy('notifications', '/api/notifications', '/internal/notifications');
createProxy('documents', '/api/documents', '/internal/documents');
createProxy('reports', '/api/reports', '/internal/reports');

startApp(app);
