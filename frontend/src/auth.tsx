import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { ShieldCheck, ArrowRight, LockKeyhole, Activity, ScanLine } from 'lucide-react';
import { configureSession, post } from './api';
import type { Session } from './types';

interface Auth {
  session: Session;
  signOut: (alreadyRevoked?: boolean) => Promise<void>;
}
const Context = createContext<Auth | null>(null);
export function useAuth() {
  const auth = useContext(Context);
  if (!auth) throw new Error('Authentication required');
  return auth;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [notice, setNotice] = useState('');
  const expire = () => {
    configureSession(null);
    setSession(null);
    setNotice('Your session has ended. Sign in to continue.');
  };
  useEffect(() => {
    if (!session) return;
    const timer = window.setTimeout(
      expire,
      Math.max(0, new Date(session.expires_at).getTime() - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [session]);
  async function signOut(alreadyRevoked = false) {
    try {
      if (!alreadyRevoked) await post('/auth/logout');
      setNotice(
        alreadyRevoked
          ? 'Password changed. Sign in with your new password.'
          : 'You have signed out.',
      );
    } catch {
      setNotice('Signed out on this device. The server session will expire automatically.');
    } finally {
      configureSession(null);
      setSession(null);
    }
  }
  if (!session)
    return (
      <Login
        notice={notice}
        onLogin={(value) => {
          configureSession(value.access_token, expire);
          setSession(value);
          setNotice('');
        }}
      />
    );
  return <Context.Provider value={{ session, signOut }}>{children}</Context.Provider>;
}

function Login({ notice, onLogin }: { notice: string; onLogin: (session: Session) => void }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <div className="login-page">
      <section className="login-story">
        <div className="brand">
          <span className="brand-symbol">
            <ShieldCheck size={24} />
          </span>
          <span>
            sentinel<span className="brand-period">.</span>
          </span>
        </div>
        <div className="login-intro">
          <span className="eyebrow">SECURITY OPERATIONS WORKSPACE</span>
          <h1>
            See the signal.
            <br />
            <span>Follow the evidence.</span>
          </h1>
          <p>
            Bring endpoint activity into focus. Monitor your environment, investigate alerts, and
            keep the full story in one place.
          </p>
          <div className="signal-art" aria-hidden="true">
            <div className="signal-ring ring-one" />
            <div className="signal-ring ring-two" />
            <div className="signal-ring ring-three" />
            <div className="signal-core">
              <ScanLine size={46} strokeWidth={1.4} />
            </div>
            <span className="signal-node node-one">
              <Activity size={22} />
            </span>
            <span className="signal-node node-two">
              <ShieldCheck size={22} />
            </span>
            <span className="signal-orbit" />
          </div>
        </div>
        <div className="login-foot">
          CROSS-PLATFORM SIEM <span>WINDOWS + macOS</span>
        </div>
      </section>
      <main className="login-main">
        <div className="login-form">
          <span className="small-icon">
            <LockKeyhole size={22} />
          </span>
          <h2>Welcome back</h2>
          <p className="muted">Sign in to your security workspace.</p>
          {notice && (
            <p className="notice" role="status">
              {notice}
            </p>
          )}
          {error && (
            <p className="error-banner" role="alert">
              {error}
            </p>
          )}
          <form
            onSubmit={async (event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const data = new FormData(form);
              setBusy(true);
              setError('');
              try {
                const result = await post<Session>('/auth/login', {
                  username: data.get('username'),
                  password: data.get('password'),
                });
                form.reset();
                onLogin(result);
              } catch (error) {
                setError((error as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label>
              Username
              <input
                name="username"
                autoComplete="username"
                required
                minLength={3}
                maxLength={64}
                placeholder="Your username"
                autoFocus
              />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                required
                minLength={12}
                maxLength={128}
                placeholder="Enter your password"
              />
            </label>
            <button className="button primary login-submit" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in to workspace'}
              <ArrowRight size={17} />
            </button>
          </form>
          <p className="login-help">
            Access is managed by your administrator.
            <br />
            Your session stays private to this browser tab.
          </p>
        </div>
        <span className="login-copyright">Sentinel · Security monitoring, with context.</span>
      </main>
    </div>
  );
}
