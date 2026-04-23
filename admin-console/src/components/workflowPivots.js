export function buildHref(path, { params, hash } = {}) {
  const search = new URLSearchParams();

  Object.entries(params || {}).forEach(([key, value]) => {
    if (value == null) return;
    const normalized = String(value).trim();
    if (!normalized) return;
    search.set(key, normalized);
  });

  const query = search.toString();
  const normalizedHash = hash ? `#${String(hash).replace(/^#/, '')}` : '';
  return `${path}${query ? `?${query}` : ''}${normalizedHash}`;
}