/**
 * Format an API error for display to the operator.
 *
 * Handles the error shape thrown by `api.request()` — which attaches a
 * `body` string and a `message` to the error — and falls back to the
 * provided `fallback` message when neither is usable.
 *
 * @param {unknown} error Thrown error or API response.
 * @param {string} fallback Human-readable message to show when no
 *   structured error information is available.
 * @returns {string}
 */
export function formatApiError(error, fallback) {
  if (error?.body) {
    try {
      const parsed = JSON.parse(error.body);
      if (typeof parsed?.error === 'string' && parsed.error) return parsed.error;
    } catch {
      /* ignore invalid error bodies */
    }
  }
  if (typeof error?.message === 'string' && error.message) return error.message;
  return fallback;
}
