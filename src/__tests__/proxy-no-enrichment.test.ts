/**
 * Confirms that BFF no longer performs DB-backed role enrichment.
 * The enrichRole middleware and x-lb-enriched-role header forwarding have been removed.
 * Role resolution is now handled exclusively by service-common requireAuth via JWT custom:role.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const INDEX_PATH = resolve(__dirname, '../../src/index.ts');

describe('BFF gateway — no role enrichment', () => {
  it('does not export or reference enrichRole middleware', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).not.toContain('enrichRole');
    expect(source).not.toContain('x-lb-enriched-role');
    expect(source).not.toContain('ENRICHED_ROLE_HEADER');
    expect(source).not.toContain('queryOne');
  });

  it('does not register PM proxy route', () => {
    const source = readFileSync(INDEX_PATH, 'utf8');
    expect(source).not.toContain('/api/pm');
    expect(source).not.toContain('/internal/pm');
  });
});
