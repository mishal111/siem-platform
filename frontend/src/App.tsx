import { Component, Suspense, lazy, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, Route, Routes, useLocation } from 'react-router';
import {
  Activity,
  Bell,
  ChevronRight,
  LayoutDashboard,
  LogOut,
  Menu,
  Monitor,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react';
import { AuthProvider, useAuth } from './auth';
import { label, Loading } from './components';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Explorer = lazy(() => import('./pages/Explorer'));
const EventDetail = lazy(() =>
  import('./pages/Explorer').then((module) => ({ default: module.EventDetail })),
);
const Investigation = lazy(() => import('./pages/Investigation'));
const Hosts = lazy(() => import('./pages/Hosts'));
const HostPage = lazy(() =>
  import('./pages/Hosts').then((module) => ({ default: module.HostPage })),
);
const Rules = lazy(() => import('./pages/Rules'));
const Account = lazy(() => import('./pages/Account'));

class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <div className="error-state" role="alert">
        <h2>This view could not be displayed</h2>
        <p>Reload the workspace to try again.</p>
        <button className="button" onClick={() => window.location.reload()}>
          Reload workspace
        </button>
      </div>
    ) : (
      this.props.children
    );
  }
}

const navigation = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/events', label: 'Event explorer', icon: Activity },
  { path: '/alerts', label: 'Alerts', icon: Bell },
  { path: '/hosts', label: 'Hosts', icon: Monitor },
  { path: '/rules', label: 'Detection rules', icon: ShieldCheck },
];

function Workspace() {
  const { session, signOut } = useAuth();
  const location = useLocation();
  const [menu, setMenu] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const main = useRef<HTMLElement>(null);
  const sidebar = useRef<HTMLElement>(null);
  const menuToggle = useRef<HTMLButtonElement>(null);
  function closeMenu() {
    setMenu(false);
    menuToggle.current?.focus();
  }
  useEffect(() => {
    if (!menu) return;
    const links = () =>
      Array.from(sidebar.current?.querySelectorAll<HTMLElement>('a, button') || []).filter(
        (element) => element.getClientRects().length > 0,
      );
    links()[0]?.focus();
    function keydown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault();
        setMenu(false);
        menuToggle.current?.focus();
      }
      if (event.key === 'Tab') {
        const items = links();
        const first = items[0];
        const last = items.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    }
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [menu]);
  const current =
    navigation.find((item) =>
      item.path === '/' ? location.pathname === '/' : location.pathname.startsWith(item.path),
    )?.label || 'Your account';
  useEffect(() => {
    document.title = `${current} · Sentinel`;
    main.current?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [location.pathname, current]);
  return (
    <div className="workspace">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      {menu && <button className="nav-overlay" aria-label="Close navigation" onClick={closeMenu} />}
      <aside ref={sidebar} className={`sidebar ${menu ? 'is-open' : ''}`}>
        <Link to="/" className="brand" onClick={() => setMenu(false)}>
          <span className="brand-symbol">
            <ShieldCheck size={23} />
          </span>
          <span>
            sentinel<span className="brand-period">.</span>
          </span>
        </Link>
        <button
          className="mobile-close icon-button"
          aria-label="Close navigation"
          onClick={closeMenu}
        >
          <X size={22} />
        </button>
        <div className="workspace-label">
          <span className="workspace-avatar">S</span>
          <div>
            <strong>Security workspace</strong>
            <span>Cross-platform SIEM</span>
          </div>
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {navigation.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              onClick={() => setMenu(false)}
            >
              <item.icon size={18} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-note">
            <ShieldCheck size={20} />
            <strong>Context for every alert.</strong>
            <p>Connect activity. Review evidence. Keep a record.</p>
          </div>
          <NavLink className="account-link" to="/account" onClick={() => setMenu(false)}>
            <span className="user-avatar">{session.user.username.slice(0, 2).toUpperCase()}</span>
            <span>
              <strong>{session.user.username}</strong>
              <small>{label(session.user.role)}</small>
            </span>
            <ChevronRight size={16} />
          </NavLink>
        </div>
      </aside>
      <div className="workspace-main">
        <header className="topbar">
          <div>
            <button
              className="mobile-menu icon-button"
              ref={menuToggle}
              aria-label="Open navigation"
              aria-expanded={menu}
              onClick={() => setMenu(true)}
            >
              <Menu size={21} />
            </button>
            <span className="topbar-label">Workspace</span>
            <ChevronRight size={13} />
            <strong>{current}</strong>
          </div>
          <div>
            <span className="session-indicator">
              <span className="status-dot" />
              Signed in as {session.user.username}
            </span>
            <button
              className="icon-button"
              title="Sign out"
              aria-label="Sign out"
              disabled={signingOut}
              onClick={async () => {
                setSigningOut(true);
                await signOut();
              }}
            >
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main id="main-content" ref={main} tabIndex={-1} className="content">
          <ErrorBoundary key={location.pathname}>
            <Suspense fallback={<Loading />}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/events" element={<Explorer kind="events" />} />
                <Route path="/events/:id" element={<EventDetail />} />
                <Route path="/alerts" element={<Explorer kind="alerts" />} />
                <Route path="/alerts/:id" element={<Investigation />} />
                <Route path="/hosts" element={<Hosts />} />
                <Route path="/hosts/:id" element={<HostPage />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/account" element={<Account />} />
                <Route
                  path="*"
                  element={
                    <div className="empty-state">
                      <UserRound size={26} />
                      <h1>Page not found</h1>
                      <p>This page does not exist in the workspace.</p>
                      <Link className="button primary" to="/">
                        Return to overview
                      </Link>
                    </div>
                  }
                />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </main>
        <footer className="app-footer">
          <span>
            Sentinel <span className="text-dot">/</span> Security operations
          </span>
          <span>Observe. Investigate. Understand.</span>
        </footer>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Workspace />
      </AuthProvider>
    </ErrorBoundary>
  );
}
