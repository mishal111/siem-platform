import { useState } from 'react';
import { post } from '../api';
import { useAuth } from '../auth';
import { Details, Heading, label, Panel, time } from '../components';

export default function Account() {
  const { session, signOut } = useAuth();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <>
      <Heading title="Your account" description="Your workspace access and sign-in security." />
      <Panel title="Profile">
        <Details
          items={[
            ['Username', session.user.username],
            ['Role', label(session.user.role)],
            ['Session expires', time(session.expires_at)],
            ['Account ID', session.user.id],
          ]}
        />
      </Panel>
      <Panel
        title="Change password"
        subtitle="Changing your password ends your active sessions. Sign in again afterward."
      >
        <form
          className="password-form"
          onSubmit={async (event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const values = new FormData(form);
            setError('');
            if (values.get('new_password') !== values.get('confirmation')) {
              setError('The new passwords do not match.');
              return;
            }
            setBusy(true);
            try {
              await post('/auth/password', {
                current_password: values.get('current_password'),
                new_password: values.get('new_password'),
              });
              form.reset();
              await signOut(true);
            } catch (error) {
              setError((error as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {error && (
            <p className="error-banner" role="alert">
              {error}
            </p>
          )}
          <label>
            Current password
            <input
              name="current_password"
              type="password"
              autoComplete="current-password"
              required
              minLength={12}
              maxLength={128}
            />
          </label>
          <label>
            New password
            <input
              name="new_password"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              maxLength={128}
            />
          </label>
          <label>
            Confirm new password
            <input
              name="confirmation"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              maxLength={128}
            />
          </label>
          <p className="muted">Use 12–128 characters.</p>
          <button className="button primary" disabled={busy}>
            {busy ? 'Updating…' : 'Change password'}
          </button>
        </form>
      </Panel>
    </>
  );
}
