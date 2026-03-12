/**
 * Validates BFF role enrichment middleware is in place.
 * The BFF resolves user roles by calling auth-service and forwards the
 * role via x-lb-enriched-role header to downstream data-plane services.
 *
 * Data-plane services cannot query the User table directly (different DB
 * credentials), so the BFF acts as the role resolution bridge.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const INDEX_PATH = resolve(__dirname, '../../src/index.ts');

describe('BFF gateway — role enrichment', () => {
  it('includes role enrichment middleware with x-lb-enriched-role header', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).toContain('x-lb-enriched-role');
    expect(source).toContain('_enrichedRole');
    expect(source).toContain('/internal/auth/me');
  });

  it('has role cache with TTL', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).toContain('roleCache');
    expect(source).toContain('ROLE_CACHE_TTL_MS');
  });

  it('skips enrichment for auth routes', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).toContain('/api/auth');
  });

  it('does not register PM proxy route', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).not.toContain('/api/pm');
    expect(source).not.toContain('/internal/pm');
  });

  it('does not use direct DB queries (queryOne)', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).not.toContain('queryOne');
  });
});
