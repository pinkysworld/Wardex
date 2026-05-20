// Defensive `localStorage` helpers — every call is wrapped so a browser that
// blocks storage (private mode, quota exceeded, sandboxed iframe, etc.) falls
// back to the supplied default instead of throwing.
//
// First TypeScript file in the per-slice console migration: utility-only, no
// React, no DOM types beyond the global `localStorage`. New files and
// converted slices should follow this shape (explicit input/return types,
// `unknown` for caller-supplied payloads, generics for JSON helpers).

export function safeStorageGet(key: string, fallback: string | null = null): string | null {
  try {
    const storage = globalThis?.localStorage;
    if (!storage) return fallback;
    const value = storage.getItem(key);
    return value === null ? fallback : value;
  } catch {
    return fallback;
  }
}

export function safeStorageSet(key: string, value: string): boolean {
  try {
    globalThis?.localStorage?.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export function safeStorageRemove(key: string): boolean {
  try {
    globalThis?.localStorage?.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

export function safeStorageJsonGet<T>(key: string, fallback: T): T {
  const raw = safeStorageGet(key);
  if (raw === null || raw === undefined || raw === '') return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function safeStorageJsonSet(key: string, value: unknown): boolean {
  try {
    return safeStorageSet(key, JSON.stringify(value));
  } catch {
    return false;
  }
}
