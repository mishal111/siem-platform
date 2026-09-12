import { useEffect, useState } from 'react';
import { api, ApiError } from './api';

export function useResource<T>(path: string | null, version = 0) {
  const [state, setState] = useState<{
    path: string | null;
    version: number;
    data?: T;
    error?: ApiError;
  }>({ path: null, version: -1 });
  useEffect(() => {
    if (!path) return;
    const controller = new AbortController();
    api<T>(path, { signal: controller.signal }).then(
      (data) => {
        if (!controller.signal.aborted) setState({ path, version, data });
      },
      (error) => {
        if (!controller.signal.aborted) setState({ path, version, error });
      },
    );
    return () => controller.abort();
  }, [path, version]);
  const current = state.path === path && state.version === version;
  return {
    data: current ? state.data : undefined,
    error: current ? state.error : undefined,
    loading: !!path && (!current || (!state.data && !state.error)),
  };
}

export function useRefresh(interval?: number) {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    if (!interval) return;
    const timer = window.setInterval(() => {
      if (!document.hidden) setVersion((value) => value + 1);
    }, interval);
    return () => window.clearInterval(timer);
  }, [interval]);
  return [version, () => setVersion((value) => value + 1)] as const;
}
