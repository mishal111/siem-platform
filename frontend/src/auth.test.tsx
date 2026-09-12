import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthProvider, useAuth } from './auth';

function PrivateView() {
  const { session, signOut } = useAuth();
  return (
    <>
      <p>Private view: {session.user.username}</p>
      <button onClick={() => void signOut()}>Logout</button>
    </>
  );
}

it('gates private content, logs in, keeps credentials out of storage, and signs out', async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'synthetic-token',
          expires_at: new Date(Date.now() + 3600000).toISOString(),
          user: { id: 'test', username: 'analyst', role: 'analyst' },
        }),
      ),
    )
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  vi.stubGlobal('fetch', fetcher);
  const user = userEvent.setup();
  render(
    <AuthProvider>
      <PrivateView />
    </AuthProvider>,
  );
  expect(screen.queryByText(/Private view/)).not.toBeInTheDocument();
  await user.type(screen.getByLabelText('Username'), 'analyst');
  await user.type(screen.getByLabelText('Password'), 'synthetic-password');
  await user.click(screen.getByRole('button', { name: /Sign in to workspace/ }));
  expect(await screen.findByText('Private view: analyst')).toBeInTheDocument();
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
  await user.click(screen.getByText('Logout'));
  expect(await screen.findByText('You have signed out.')).toBeInTheDocument();
  expect(screen.queryByText(/Private view/)).not.toBeInTheDocument();
});

it('keeps failed logins on the sign-in screen and explains the error', async () => {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValue(
        new Response('{"detail":"Invalid username or password"}', { status: 401 }),
      ),
  );
  const user = userEvent.setup();
  render(
    <AuthProvider>
      <PrivateView />
    </AuthProvider>,
  );
  await user.type(screen.getByLabelText('Username'), 'analyst');
  await user.type(screen.getByLabelText('Password'), 'synthetic-password');
  await user.click(screen.getByRole('button', { name: /Sign in to workspace/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password');
  expect(screen.queryByText(/Private view/)).not.toBeInTheDocument();
});
