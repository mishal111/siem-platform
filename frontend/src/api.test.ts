import { describe, expect, it, vi } from 'vitest';
import { api, configureSession, post, query } from './api';

describe('API session and failure behavior', () => {
  it('sends a bearer token only to the same-origin API, without cookies or caching', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{}'));
    vi.stubGlobal('fetch', fetcher);
    configureSession('synthetic-token');
    await api('/events');
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/events',
      expect.objectContaining({
        credentials: 'omit',
        redirect: 'error',
        cache: 'no-store',
        headers: { Authorization: 'Bearer synthetic-token' },
      }),
    );
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    await expect(api('https://untrusted.invalid')).rejects.toThrow('Invalid API path');
    await expect(api('//untrusted.invalid')).rejects.toThrow('Invalid API path');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('expires a rejected session and propagates the failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('{"detail":"Invalid session"}', { status: 401 })),
    );
    const expire = vi.fn();
    configureSession('synthetic-token', expire);
    await expect(api('/events')).rejects.toMatchObject({ status: 401 });
    expect(expire).toHaveBeenCalledOnce();
  });
  it('does not let an old unauthorized request clear a newer session', async () => {
    let finish!: (response: Response) => void;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockReturnValue(
        new Promise<Response>((resolve) => {
          finish = resolve;
        }),
      ),
    );
    const expire = vi.fn();
    configureSession('old-token', expire);
    const pending = api('/events');
    configureSession('new-token', expire);
    finish(new Response('{}', { status: 401 }));
    await expect(pending).rejects.toMatchObject({ status: 401 });
    expect(expire).not.toHaveBeenCalled();
  });
  it('retains throttle metadata without silently retrying a mutation', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(new Response('{}', { status: 429, headers: { 'Retry-After': '30' } }));
    vi.stubGlobal('fetch', fetcher);
    await expect(post('/alerts/example/notes', { text: 'Synthetic' })).rejects.toMatchObject({
      status: 429,
      retryAfter: '30',
    });
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('accepts empty logout responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(post('/auth/logout')).resolves.toBeUndefined();
  });
  it('does not expire a valid session for an incorrect current password', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response('{"detail":"Current password is incorrect"}', { status: 401 }),
        ),
    );
    const expire = vi.fn();
    configureSession('synthetic-token', expire);
    await expect(post('/auth/password', {})).rejects.toMatchObject({ status: 401 });
    expect(expire).not.toHaveBeenCalled();
  });
  it('provides a useful offline error without leaking raw network details', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('private network detail')));
    await expect(api('/events')).rejects.toMatchObject({
      status: 0,
      message: 'Cannot reach the backend. Check that the services are running.',
    });
  });
  it('encodes exact filters and omits empty values without dropping zero', () => {
    expect(query({ hostname: 'host & one', limit: 0, cursor: '', os: null })).toBe(
      '?hostname=host+%26+one&limit=0',
    );
  });
});
