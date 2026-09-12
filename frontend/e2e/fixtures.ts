import { expect, type Page } from '@playwright/test';
export const stamp = '2026-09-12T12:00:00Z';
export const user = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'demo-analyst',
  role: 'analyst',
  active: true,
  revision: 0,
  created_at: stamp,
};
export const alert = {
  id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
  rule_id: 'AUTH-BRUTE-001',
  rule_name: 'Repeated failed logins',
  rule_version: 2,
  severity: 'high',
  status: 'open',
  revision: 0,
  assigned_to: null,
  note_count: 0,
  hostname: 'SYNTHETIC-WIN-LAB',
  endpoint_id: 'test-host',
  os: 'windows',
  username: 'synthetic-user',
  source_ip: '192.0.2.7',
  description: 'Synthetic fixture: five matching login failures in five minutes.',
  mitre_technique: 'T1110',
  mitre_name: 'Brute Force',
  event_count: 1,
  first_seen: stamp,
  last_seen: stamp,
  created_at: stamp,
};
export const event = {
  id: 'bbbbbbbbbbbbbbbbbbbbbbbb',
  event_uid: '22222222-2222-4222-8222-222222222222',
  endpoint_id: 'test-host',
  timestamp: stamp,
  received_at: stamp,
  hostname: 'SYNTHETIC-WIN-LAB',
  os: 'windows',
  source: 'Security',
  event_type: 'login_failure',
  event_code: 4625,
  username: 'synthetic-user',
  source_ip: '192.0.2.7',
  severity: 'medium',
  message: 'Synthetic test telemetry',
  raw_event: { sample: '<img src=x onerror=alert(1)>' },
};
export const host = {
  endpoint_id: 'test-host',
  hostname: 'SYNTHETIC-WIN-LAB',
  os: 'windows',
  first_seen_at: stamp,
  last_seen_at: stamp,
  last_heartbeat_at: null,
  last_event_received_at: stamp,
  collector_version: null,
  pending: null,
  rejected: null,
  source_error: null,
};
export const summary = {
  as_of: stamp,
  start_time: stamp,
  end_time: stamp,
  event_count: 3214,
  alert_count: 18,
  alerts_by_status: { open: 12, investigating: 3, resolved: 3 },
  alerts_by_severity: { critical: 2, high: 8, medium: 6, low: 2 },
  events_by_os: { windows: 2410, macos: 804 },
  events_by_type: { login_failure: 2500 },
  alerts_by_rule: {},
  recently_reporting_hosts: 2,
  top_hosts: [],
  top_source_ips: [],
  events_per_hour: Array.from({ length: 25 }, (_, index) => ({
    timestamp: new Date(Date.parse(stamp) - (24 - index) * 3600000).toISOString(),
    count: [
      15, 28, 20, 36, 17, 21, 85, 152, 124, 96, 173, 201, 164, 123, 160, 142, 93, 65, 80, 119, 92,
      108, 53, 66, 42,
    ][index],
  })),
};

export async function mockBackend(page: Page, role = 'analyst') {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/api/v1', '');
    let body: unknown;
    if (path === '/auth/login')
      body = {
        access_token: 'synthetic-browser-token',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        user: { ...user, role },
      };
    else if (path === '/auth/logout') {
      await route.fulfill({ status: 204 });
      return;
    } else if (path === '/dashboard/summary') body = summary;
    else if (path === '/detections/status')
      body = {
        worker_recent: true,
        worker_last_seen_at: stamp,
        worker_last_error: null,
        events: { pending: 0, processed: 3214, failed: 0 },
      };
    else if (path === '/detections/rules')
      body = [
        {
          rule_id: alert.rule_id,
          name: alert.rule_name,
          severity: 'high',
          enabled: true,
          version: 2,
          description: alert.description,
          mitre_technique: 'T1110',
          mitre_name: 'Brute Force',
          threshold: 5,
          window_seconds: 300,
          group_by: [],
          event_requirements: { event_type: 'login_failure' },
        },
      ];
    else if (path === '/alerts') body = { items: [alert], next_cursor: null };
    else if (path === '/alerts/' + alert.id) body = alert;
    else if (path.endsWith('/events') && path.startsWith('/alerts/'))
      body = { items: [event], missing_event_ids: [] };
    else if (path.endsWith('/notes')) body = [];
    else if (path.endsWith('/history')) body = { items: [], next_revision: null };
    else if (path === '/users/directory') body = { items: [user], next_cursor: null };
    else if (path === '/events') body = { items: [event], next_cursor: null };
    else if (path === '/events/' + event.id) body = event;
    else if (path === '/hosts') body = { items: [host], next_cursor: null };
    else if (path === '/hosts/test-host')
      body = {
        host,
        event_count: 16,
        alert_count: 1,
        recent_events: [event],
        recent_alerts: [alert],
      };
    else {
      await route.fulfill({ status: 404, json: { detail: 'Test route not found' } });
      return;
    }
    await route.fulfill({ json: body });
  });
}
export async function login(page: Page, path = '/') {
  await page.goto(path);
  await page.getByLabel('Username', { exact: true }).fill('demo-analyst');
  await page.getByLabel('Password', { exact: true }).fill('synthetic-password');
  await page.getByRole('button', { name: /Sign in to workspace/ }).click();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
}
