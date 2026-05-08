export function safeStorageGet(key, fallback = null) {
  try {
    const storage = globalThis?.localStorage;
    if (!storage) return fallback;
    const value = storage.getItem(key);
    return value === null ? fallback : value;
  } catch {
    return fallback;
  }
}

export function safeStorageSet(key, value) {
  try {
    globalThis?.localStorage?.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export function safeStorageRemove(key) {
  try {
    globalThis?.localStorage?.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

export function safeStorageJsonGet(key, fallback) {
  const raw = safeStorageGet(key);
  if (raw === null || raw === undefined || raw === '') return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

export function safeStorageJsonSet(key, value) {
  try {
    return safeStorageSet(key, JSON.stringify(value));
  } catch {
    return false;
  }
}
