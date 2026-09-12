# Sentinel analyst workspace

The first frontend milestone uses React, TypeScript, Vite, React Router, Recharts,
and Lucide icons. It connects to the existing SIEM API through same-origin requests.
The application uses backend data; synthetic fixtures appear only in automated tests.

## Open the application

From the project root:

```bash
docker compose --profile frontend up --build -d --wait frontend worker
```

Open **http://127.0.0.1:5173**. Sign in using the account in
`.local/admin-credentials.json`, unless its password has since changed. On a new
checkout, run `python3 scripts/init_env.py` before Compose, then
`python3 scripts/bootstrap_admin.py` once the backend is healthy. No credentials
are embedded in the frontend bundle.

The frontend container serves the production build and proxies `/api/*` to the
development backend. It publishes only loopback port 5173, supports nested routes,
and sets a same-origin Content Security Policy. Assets have immutable caching;
API responses remain uncached. The separate `deploy/compose.yml` HTTPS stack
retains its API-only configuration. Public HTTPS frontend hosting is future work.

## Implemented views

| View              | Behavior                                                                     |
| ----------------- | ---------------------------------------------------------------------------- |
| Login and account | Sign in/out, session expiry, role display, password change                   |
| Overview          | Live counts, hourly activity, severity, recent alerts, sources, worker state |
| Event explorer    | Exact filters, time ranges, server pagination, raw-record details            |
| Alert queue       | Status/severity/rule/host filters, pagination, investigation links           |
| Investigation     | Evidence, status, assignment, notes, audit history, conflict recovery        |
| Hosts             | Observed inventory, host details, recent events and alerts                   |
| Detection rules   | Configured rules, matching requirements, MITRE mappings, linked alerts       |

Viewer accounts can read investigations but cannot submit changes. Backend
authorization remains authoritative. Conflicting edits require an explicit reload
and review; draft notes survive this reload. Retrying an ambiguous note submission
reuses its UUID. Navigating away does not save an unsubmitted draft.

Tokens live **only in memory**. Refreshing or closing the browser tab requires
sign-in again. Credentials are never written to localStorage, sessionStorage,
cookies, URLs, or frontend environment variables. Logout revokes the server session;
when the backend is unreachable, local logout clears the tab and explains that the
server session will expire automatically.

The overview refreshes every 30 seconds while visible. Other pages use manual
refresh. Charts use event receipt time; event search uses source event time; alerts
use creation time. Times are shown in the browser's timezone. Loading, empty,
connection-error, expired-session, and stale-edit states are explicit. A quiet host
is not labeled offline. Missing heartbeat data is shown as not reported; native
collector heartbeat scheduling remains separate work.

## Development

Use Node.js 24 and the committed lockfile:

```bash
# From the project root; stop the container if it occupies port 5173:
docker compose --profile frontend stop frontend
cd frontend
npm ci
npm run dev
```

Vite binds to `127.0.0.1:5173` and proxies `/api` to `http://127.0.0.1:8000`.
`SIEM_PROXY_TARGET` overrides this server-side proxy target. Default setup needs
no CORS changes and reads no root `.env` credentials. The backend and worker must
be running for real data.

`npm run build` checks TypeScript and generates route-split assets in `dist/`.
`npm run preview` serves static assets on port 4173; the API-integrated production
setup is the Compose service.

## Verification

```bash
cd frontend
npm test
npm run build
npm run format:check
PLAYWRIGHT_BROWSERS_PATH=../.local/playwright npx playwright install chromium
PLAYWRIGHT_BROWSERS_PATH=../.local/playwright npm run test:e2e
```

The standard browser suite intercepts the API with synthetic fixtures. It tests
navigation, exact filters, pagination, viewer restrictions, conflicting edits,
idempotent note retries, raw telemetry rendered as text, expired sessions,
offline/empty recovery, and mobile layout/navigation. It never logs into the real API.

Opt in to real backend validation against the running development stack:

```bash
RUN_LIVE_UI=1 UI_EXTERNAL_SERVER=1 PLAYWRIGHT_BROWSERS_PATH=../.local/playwright npm run test:e2e -- e2e/live.spec.ts
```

This test privately reads the local administrator credentials, creates two
temporary users and a synthetic endpoint/event, and waits for a real worker
detection. It checks browser login, filters, evidence, assignment, status, notes,
history, viewer access, and logout. Cleanup deactivates its users and revokes its
endpoint. Clearly labeled synthetic telemetry/history remain reviewable. Existing
alerts are not modified and no real endpoint security activity is generated.

Screenshots and results are saved in gitignored `.local/`. Screenshots are taken
after login; traces, videos, and automatic screenshots are disabled to avoid
recording credentials. `UI_BASE_URL` overrides the test origin. Set
`UI_EXTERNAL_SERVER=1` to use a running Compose frontend. An optional
`PW_CHROMIUM_EXECUTABLE` selects an installed Chromium-compatible browser; tests
always launch a separate temporary profile.

## Remaining scope

User administration and endpoint enrollment/rotation still use the API or Swagger.
Their management screens, saved searches, exports, notifications, persistent
login/SSO, and public HTTPS frontend hosting remain later milestones. Native
Windows VM validation is deferred.

See [backend integration](../docs/backend-api.md). Implementation references:
[Vite](https://vite.dev/guide/),
[React Router](https://reactrouter.com/start/declarative/installation), and
[Playwright network testing](https://playwright.dev/docs/network).
