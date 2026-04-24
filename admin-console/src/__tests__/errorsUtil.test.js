import { describe, it, expect } from 'vitest';
import { formatApiError } from '../utils/errors.js';

describe('formatApiError', () => {
  it('returns the server-provided error string from a JSON body', () => {
    const error = { body: JSON.stringify({ error: 'retention bucket invalid' }) };
    expect(formatApiError(error, 'fallback')).toBe('retention bucket invalid');
  });

  it('falls back to error.message when the body is missing', () => {
    const error = { message: 'network disconnected' };
    expect(formatApiError(error, 'fallback')).toBe('network disconnected');
  });

  it('returns the fallback when the body is malformed JSON', () => {
    const error = { body: '<html>boom</html>' };
    expect(formatApiError(error, 'default message')).toBe('default message');
  });

  it('returns the fallback when the JSON body has no error field', () => {
    const error = { body: JSON.stringify({ status: 'ok' }) };
    expect(formatApiError(error, 'default message')).toBe('default message');
  });

  it('returns the fallback when the error has neither body nor message', () => {
    expect(formatApiError({}, 'fallback')).toBe('fallback');
    expect(formatApiError(null, 'fallback')).toBe('fallback');
    expect(formatApiError(undefined, 'fallback')).toBe('fallback');
  });

  it('prefers the parsed JSON error over error.message', () => {
    const error = {
      body: JSON.stringify({ error: 'server-side detail' }),
      message: 'network disconnected',
    };
    expect(formatApiError(error, 'fallback')).toBe('server-side detail');
  });

  it('ignores an empty-string error field in the JSON body', () => {
    const error = {
      body: JSON.stringify({ error: '' }),
      message: 'network disconnected',
    };
    expect(formatApiError(error, 'fallback')).toBe('network disconnected');
  });
});
