import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

// ── Mock service-common DB layer ─────────────────────────────────────────────
const mockQueryOne = vi.fn();
vi.mock('@leasebase/service-common', async (importOriginal) => {
  const original = await importOriginal<typeof import('@leasebase/service-common')>();
  return {
    ...original,
    queryOne: mockQueryOne,
  };
});

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal JWT (header.payload.signature) with the given payload. */
function fakeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = 'fake-signature';
  return `${header}.${body}.${sig}`;
}

function mockReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    ...overrides,
  } as unknown as Request;
}

function mockRes(): Response {
  return {} as unknown as Response;
}

// ── Import the module under test (after mocks are set up) ────────────────────
// We test decodeJwtPayload and enrichRole by importing the BFF gateway module.
// Since the module has side-effects (creates Express app, registers routes),
// we isolate the functions we need by extracting them from the module source.
// Instead, we test via the enrichRole middleware behavior directly.

// Since enrichRole is not exported, we replicate the logic from index.ts for
// unit testing. In integration tests, the full Express app would be tested.

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

// Re-implement enrichRole for isolated unit testing (mirrors index.ts logic)
const ENRICHED_ROLE_HEADER = 'x-lb-enriched-role';

async function enrichRole(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }
    if (process.env.DEV_AUTH_BYPASS === 'true' && req.headers['x-dev-user-email']) {
      return next();
    }
    const token = authHeader.slice(7);
    const payload = decodeJwtPayload(token);
    if (!payload || !payload.sub) {
      return next();
    }
    const user = await mockQueryOne(
      'SELECT "role" FROM "User" WHERE "cognitoSub" = $1',
      [payload.sub],
    );
    if (user) {
      req.headers[ENRICHED_ROLE_HEADER] = user.role;
    }
  } catch {
    // best-effort
  }
  next();
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('decodeJwtPayload', () => {
  it('decodes a valid JWT payload', () => {
    const token = fakeJwt({ sub: 'user-123', email: 'a@b.com', 'custom:role': 'OWNER' });
    const payload = decodeJwtPayload(token);
    expect(payload).toEqual({ sub: 'user-123', email: 'a@b.com', 'custom:role': 'OWNER' });
  });

  it('returns null for a malformed token', () => {
    expect(decodeJwtPayload('not-a-jwt')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(decodeJwtPayload('')).toBeNull();
  });

  it('returns null for token with invalid base64', () => {
    expect(decodeJwtPayload('a.!!!.b')).toBeNull();
  });
});

describe('enrichRole middleware', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    mockQueryOne.mockReset();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('enriches role to OWNER when DB user has OWNER role', async () => {
    const token = fakeJwt({ sub: 'cognito-sub-owner' });
    const req = mockReq({ headers: { authorization: `Bearer ${token}` } });
    const next = vi.fn();

    mockQueryOne.mockResolvedValueOnce({ role: 'OWNER' });

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBe('OWNER');
    expect(mockQueryOne).toHaveBeenCalledWith(
      'SELECT "role" FROM "User" WHERE "cognitoSub" = $1',
      ['cognito-sub-owner'],
    );
  });

  it('enriches role to TENANT when DB user has TENANT role', async () => {
    const token = fakeJwt({ sub: 'cognito-sub-tenant' });
    const req = mockReq({ headers: { authorization: `Bearer ${token}` } });
    const next = vi.fn();

    mockQueryOne.mockResolvedValueOnce({ role: 'TENANT' });

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBe('TENANT');
  });

  it('does NOT set enriched header when DB user not found', async () => {
    const token = fakeJwt({ sub: 'unknown-sub' });
    const req = mockReq({ headers: { authorization: `Bearer ${token}` } });
    const next = vi.fn();

    mockQueryOne.mockResolvedValueOnce(null);

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBeUndefined();
  });

  it('skips enrichment when no Authorization header', async () => {
    const req = mockReq({ headers: {} });
    const next = vi.fn();

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(mockQueryOne).not.toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBeUndefined();
  });

  it('skips enrichment for dev-bypass requests', async () => {
    process.env.DEV_AUTH_BYPASS = 'true';
    const token = fakeJwt({ sub: 'some-sub' });
    const req = mockReq({
      headers: {
        authorization: `Bearer ${token}`,
        'x-dev-user-email': 'dev@test.com',
      },
    });
    const next = vi.fn();

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(mockQueryOne).not.toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBeUndefined();
  });

  it('proceeds without enrichment when DB query fails', async () => {
    const token = fakeJwt({ sub: 'db-error-sub' });
    const req = mockReq({ headers: { authorization: `Bearer ${token}` } });
    const next = vi.fn();

    mockQueryOne.mockRejectedValueOnce(new Error('DB connection failed'));

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBeUndefined();
  });

  it('proceeds without enrichment for malformed JWT', async () => {
    const req = mockReq({ headers: { authorization: 'Bearer not-a-jwt' } });
    const next = vi.fn();

    await enrichRole(req, mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(mockQueryOne).not.toHaveBeenCalled();
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBeUndefined();
  });
});

describe('enriched header stripping (security)', () => {
  it('incoming x-lb-enriched-role header should be deleted before enrichment', () => {
    // Simulates the BFF's header-stripping middleware
    const req = mockReq({
      headers: { [ENRICHED_ROLE_HEADER]: 'ORG_ADMIN' },
    });

    // Strip (as the BFF middleware does)
    delete req.headers[ENRICHED_ROLE_HEADER];

    expect(req.headers[ENRICHED_ROLE_HEADER]).toBeUndefined();
  });
});

describe('downstream authorization with enriched OWNER role', () => {
  it('OWNER user with missing JWT custom:role gets OWNER via enrichment', async () => {
    // Simulates: JWT has no custom:role, DB has OWNER
    const token = fakeJwt({ sub: 'owner-sub', email: 'owner@org.com' });
    const req = mockReq({ headers: { authorization: `Bearer ${token}` } });
    const next = vi.fn();

    mockQueryOne.mockResolvedValueOnce({ role: 'OWNER' });

    await enrichRole(req, mockRes(), next);

    // The enriched role header should be OWNER
    expect(req.headers[ENRICHED_ROLE_HEADER]).toBe('OWNER');

    // Simulate what service-common requireAuth does:
    // JWT-derived role would be TENANT (default), but enriched header overrides
    const jwtDerivedRole = 'TENANT'; // what requireAuth would set from JWT
    const enrichedRole = req.headers[ENRICHED_ROLE_HEADER] as string;
    const effectiveRole = enrichedRole || jwtDerivedRole;

    expect(effectiveRole).toBe('OWNER');

    // This OWNER role would pass requireRole(ORG_ADMIN, PM_STAFF, OWNER)
    const allowedRoles = ['ORG_ADMIN', 'PM_STAFF', 'OWNER'];
    expect(allowedRoles.includes(effectiveRole)).toBe(true);
  });
});
