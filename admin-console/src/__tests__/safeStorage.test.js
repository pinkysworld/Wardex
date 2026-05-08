import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  safeStorageGet,
  safeStorageJsonGet,
  safeStorageJsonSet,
  safeStorageRemove,
  safeStorageSet,
} from '../safeStorage.js';

describe('safeStorage', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('reads and writes JSON values when storage is available', () => {
    expect(safeStorageJsonSet('wardex_test', { ok: true })).toBe(true);
    expect(safeStorageJsonGet('wardex_test', {})).toEqual({ ok: true });
    expect(safeStorageGet('wardex_test_missing', 'fallback')).toBe('fallback');
    expect(safeStorageRemove('wardex_test')).toBe(true);
  });

  it('falls back cleanly when localStorage throws', () => {
    vi.stubGlobal('localStorage', {
      getItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
      removeItem: () => {
        throw new Error('denied');
      },
    });

    expect(safeStorageGet('wardex_test', 'fallback')).toBe('fallback');
    expect(safeStorageJsonGet('wardex_test', [])).toEqual([]);
    expect(safeStorageSet('wardex_test', 'value')).toBe(false);
    expect(safeStorageRemove('wardex_test')).toBe(false);
  });
});
