import { test, expect } from '@playwright/test';
import { alert, event, login, mockBackend, summary, user } from './fixtures';

test('dashboard, deep navigation, raw evidence and sign-out', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await mockBackend(page);
  await login(page);
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  await expect(page.getByText('3,214', { exact: true }).first()).toBeVisible();
  await page.getByRole('navigation').getByRole('link', { name: 'Event explorer' }).click();
  await page.getByRole('link', { name: 'Login Failure', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Event details' })).toBeVisible();
  await expect(page.locator('pre')).toContainText('<img src=x onerror=alert(1)>');
  expect(await page.locator('pre img').count()).toBe(0);
  await page.getByRole('navigation').getByRole('link', { name: 'Hosts', exact: true }).click();
  await page.getByRole('link', { name: 'SYNTHETIC-WIN-LAB', exact: true }).click();
  await expect(page.getByText('16', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('exact filters page across server results and reset pagination when changed', async ({
  page,
}) => {
  await mockBackend(page);
  const searches: URL[] = [];
  await page.route('**/api/v1/events?*', async (route) => {
    const url = new URL(route.request().url());
    searches.push(url);
    await route.fulfill({
      json: {
        items: [
          {
            ...event,
            event_type: url.searchParams.has('cursor') ? 'login_success' : 'login_failure',
          },
        ],
        next_cursor: url.searchParams.has('cursor') ? null : 'synthetic-next-cursor',
      },
    });
  });
  await login(page, '/events');
  await page.getByLabel('Hostname', { exact: true }).fill('SYNTHETIC-WIN-LAB');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('link', { name: 'Login Failure', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('link', { name: 'Login Success', exact: true })).toBeVisible();
  expect(searches.at(-1)!.searchParams.get('hostname')).toBe('SYNTHETIC-WIN-LAB');
  expect(searches.at(-1)!.searchParams.get('cursor')).toBe('synthetic-next-cursor');
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.getByRole('link', { name: 'Login Failure', exact: true })).toBeVisible();
  expect(searches.at(-1)!.searchParams.has('cursor')).toBe(false);
  expect(searches.at(-1)!.searchParams.has('hostname')).toBe(false);
});

test('viewer can read evidence but cannot submit investigation edits', async ({ page }) => {
  await mockBackend(page, 'viewer');
  await login(page, `/alerts/${alert.id}`);
  await expect(page.getByRole('heading', { name: 'Supporting evidence' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add note' })).toHaveCount(0);
  await expect(page.getByRole('combobox', { name: 'Status', exact: true })).toBeDisabled();
});

test('conflicting edits require review and note retry keeps the same UUID', async ({ page }) => {
  await mockBackend(page);
  let conflict = true;
  let revision = 0;
  const noteBodies: { text: string; note_id: string; expected_revision: number }[] = [];
  let storedNote: object | null = null;
  await page.route(`**/api/v1/alerts/${alert.id}`, async (route) => {
    if (route.request().method() === 'PATCH') {
      if (conflict) {
        conflict = false;
        revision = 1;
        await route.fulfill({ status: 409, json: { detail: 'Stale revision' } });
        return;
      }
      revision++;
    }
    await route.fulfill({ json: { ...alert, revision } });
  });
  await page.route(`**/api/v1/alerts/${alert.id}/notes`, async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      noteBodies.push(body);
      storedNote = {
        id: body.note_id,
        text: body.text,
        actor_id: user.id,
        created_at: alert.created_at,
      };
      if (noteBodies.length === 1) {
        await route.abort('failed');
        return;
      }
      await route.fulfill({ status: 201, json: storedNote });
    } else await route.fulfill({ json: storedNote ? [storedNote] : [] });
  });
  await login(page, `/alerts/${alert.id}`);
  await page.getByLabel('Add a note').fill('Synthetic browser note');
  await page.getByRole('combobox', { name: 'Status', exact: true }).selectOption('investigating');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByRole('alert')).toContainText('This alert changed');
  await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  await page.getByRole('button', { name: 'Reload alert' }).click();
  await expect(page.getByLabel('Add a note')).toHaveValue('Synthetic browser note');
  await page.getByRole('button', { name: 'Add note' }).click();
  await expect(page.getByRole('alert')).toContainText('Cannot reach');
  await page.getByRole('button', { name: 'Add note' }).click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Note added to the investigation.' }),
  ).toBeVisible();
  expect(noteBodies).toHaveLength(2);
  expect(noteBodies[0].note_id).toBe(noteBodies[1].note_id);
  expect(noteBodies[1].expected_revision).toBe(1);
  await expect(page.getByText('Synthetic browser note', { exact: true })).toBeVisible();
});

test('expired sessions return to login and a browser reload does not persist credentials', async ({
  page,
}) => {
  await mockBackend(page);
  await login(page);
  await page.route('**/api/v1/events?*', (route) =>
    route.fulfill({ status: 401, json: { detail: 'Invalid session' } }),
  );
  await page.getByRole('navigation').getByRole('link', { name: 'Event explorer' }).click();
  await expect(page.getByText('Your session has ended. Sign in to continue.')).toBeVisible();
  await page.unroute('**/api/v1/events?*');
  await login(page);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
});

test('offline and empty states recover without fabricated metrics', async ({ page }) => {
  await mockBackend(page);
  let unavailable = true;
  await page.route('**/api/v1/dashboard/summary?*', (route) =>
    unavailable
      ? route.fulfill({ status: 503, json: { detail: 'Unavailable' } })
      : route.fulfill({
          json: {
            ...summary,
            event_count: 0,
            alert_count: 0,
            alerts_by_status: {},
            alerts_by_severity: {},
            events_by_os: {},
            recently_reporting_hosts: 0,
            events_per_hour: [],
          },
        }),
  );
  await login(page);
  await expect(page.getByRole('alert')).toContainText('temporarily unavailable');
  await expect(page.getByText('Events received', { exact: true })).toHaveCount(0);
  unavailable = false;
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByText('Awaiting telemetry')).toBeVisible();
  await expect(page.getByText('Events received', { exact: true })).toBeVisible();
});

test('password changes validate confirmation, preserve a valid session on error, then require login', async ({
  page,
}) => {
  await mockBackend(page);
  let requests = 0;
  await page.route('**/api/v1/auth/password', async (route) => {
    requests++;
    await route.fulfill(
      requests === 1
        ? { status: 401, json: { detail: 'Current password is incorrect' } }
        : { json: { ...user, revision: 1 } },
    );
  });
  await login(page, '/account');
  await page.getByLabel('Current password', { exact: true }).fill('incorrect-synthetic-password');
  await page.getByLabel('New password', { exact: true }).fill('new-synthetic-password');
  await page
    .getByLabel('Confirm new password', { exact: true })
    .fill('mismatched-synthetic-password');
  await page.getByRole('button', { name: 'Change password', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('The new passwords do not match.');
  expect(requests).toBe(0);
  await page.getByLabel('Confirm new password', { exact: true }).fill('new-synthetic-password');
  await page.getByRole('button', { name: 'Change password', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Current password is incorrect');
  await expect(page.getByRole('heading', { name: 'Your account' })).toBeVisible();
  await page.getByLabel('Current password', { exact: true }).fill('correct-synthetic-password');
  await page.getByRole('button', { name: 'Change password', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.getByRole('status')).toHaveText(
    'Password changed. Sign in with your new password.',
  );
  expect(requests).toBe(2);
});

test('mobile navigation works and pages stay within the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockBackend(page);
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill('demo-analyst');
  await page.getByLabel('Password', { exact: true }).fill('synthetic-password');
  await page.getByRole('button', { name: /Sign in to workspace/ }).click();
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused();
  await expect(page.getByRole('navigation')).not.toBeVisible();
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await page.getByRole('navigation').getByRole('link', { name: 'Alerts', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
