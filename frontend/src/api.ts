export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public retryAfter: string | null = null,
  ) {
    super(message);
  }
}

// Credentials deliberately live only in memory, never in browser storage or build variables.
let token: string | null = null;
let expireSession: () => void = () => {};
export function configureSession(value: string | null, onExpire: () => void = () => {}) {
  token = value;
  expireSession = onExpire;
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Invalid API path');
  const requestToken = token;
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) abort();
  const timer = window.setTimeout(abort, 15000);
  try {
    const response = await fetch('/api/v1' + path, {
      ...options,
      signal: controller.signal,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      headers: {
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
        ...(requestToken ? { Authorization: `Bearer ${requestToken}` } : {}),
      },
    });
    if (response.status === 204) return undefined as T;
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const incorrectCurrentPassword =
        path === '/auth/password' && body?.detail === 'Current password is incorrect';
      if (
        response.status === 401 &&
        !incorrectCurrentPassword &&
        requestToken &&
        requestToken === token
      )
        expireSession();
      let message =
        typeof body?.detail === 'string' ? body.detail : 'The request could not be completed.';
      if (Array.isArray(body?.detail))
        message = body.detail
          .map(
            (item: { loc?: string[]; msg?: string }) =>
              `${item.loc?.slice(1).join('.') || 'Request'}: ${item.msg || 'Invalid value'}`,
          )
          .join('; ');
      if (response.status === 429)
        message = 'Too many requests. Wait a moment before trying again.';
      if (response.status >= 500)
        message = 'The backend is temporarily unavailable. Please try again.';
      throw new ApiError(response.status, message, response.headers.get('Retry-After'));
    }
    if (body === null) throw new ApiError(502, 'The server returned an unexpected response.');
    return body as T;
  } catch (error) {
    if (error instanceof ApiError || options.signal?.aborted) throw error;
    throw new ApiError(
      0,
      controller.signal.aborted
        ? 'The request timed out. Please try again.'
        : 'Cannot reach the backend. Check that the services are running.',
    );
  } finally {
    window.clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
  }
}

export function query(values: Record<string, string | number | null | undefined>): string {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== '' && value != null) params.set(key, String(value));
  });
  return params.toString() ? '?' + params.toString() : '';
}

export const post = <T>(path: string, body?: unknown) =>
  api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
