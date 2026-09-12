import { test, expect } from '@playwright/test';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import type { AlertRecord, Page, Session, User } from '../src/types';

test('live backend: login, detection, evidence, assignment, notes, roles and logout', async ({
  page,
  baseURL,
}) => {
  test.skip(
    process.env.RUN_LIVE_UI !== '1',
    'Opt in to creating labeled synthetic data in the development database.',
  );
  test.setTimeout(90000);
  const credentials = JSON.parse(
    await readFile(new URL('../../.local/admin-credentials.json', import.meta.url), 'utf8'),
  );
  const origin = baseURL || 'http://127.0.0.1:5173';
  let adminToken = '';
  async function request<T>(
    path: string,
    method = 'GET',
    body?: unknown,
    key?: string,
  ): Promise<T> {
    const response = await fetch(origin + '/api/v1' + path, {
      method,
      redirect: 'error',
      headers: {
        'Content-Type': 'application/json',
        ...(key
          ? { 'X-API-Key': key }
          : adminToken
            ? { Authorization: 'Bearer ' + adminToken }
            : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok)
      throw new Error(
        `Live setup/check failed: ${method} ${path.split('?')[0]} returned ${response.status}`,
      );
    return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
  }
  const admin = await request<Session>('/auth/login', 'POST', {
    username: credentials.username,
    password: credentials.password,
  });
  adminToken = admin.access_token;
  const run = randomUUID();
  const hostname = 'SYNTHETIC-FRONTEND-' + run.slice(0, 8);
  const users: User[] = [];
  let enrolled = false;
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  const screenshots = new URL('../../.local/frontend-screenshots/', import.meta.url);
  await mkdir(screenshots, { recursive: true });
  try {
    const password = randomBytes(24).toString('base64url');
    for (const role of ['analyst', 'viewer'])
      users.push(
        await request<User>('/users', 'POST', {
          username: 'ui-' + role + '-' + run.slice(0, 8),
          password,
          role,
        }),
      );
    const endpoint = await request<{ api_key: string }>('/endpoints', 'POST', {
      endpoint_id: run,
      hostname,
      os: 'windows',
    });
    enrolled = true;
    await request(
      '/events',
      'POST',
      {
        event_uid: randomUUID(),
        endpoint_id: run,
        hostname,
        os: 'windows',
        source: 'Security',
        timestamp: new Date().toISOString(),
        event_type: 'account_created',
        event_code: 4720,
        username: 'synthetic-target',
        severity: 'medium',
        message: 'Synthetic frontend browser acceptance test: account creation',
        raw_event: { synthetic: true, test_run: run },
      },
      endpoint.api_key,
    );
    let record: AlertRecord | undefined;
    await expect
      .poll(
        async () => {
          const result = await request<Page<AlertRecord>>('/alerts?endpoint_id=' + run);
          record = result.items[0];
          return result.items.length;
        },
        { timeout: 25000 },
      )
      .toBe(1);
    const alertId = record!.id;
    async function signIn(user: User) {
      await page.getByLabel('Username', { exact: true }).fill(user.username);
      await page.getByLabel('Password', { exact: true }).fill(password);
      await page.getByRole('button', { name: /Sign in to workspace/ }).click();
    }
    await page.goto('/');
    await signIn(users[0]);
    await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
    await expect(page.getByText('Events received', { exact: true })).toBeVisible();
    await page.screenshot({
      path: new URL('dashboard-live.png', screenshots).pathname,
      fullPage: true,
    });
    await page.getByRole('navigation').getByRole('link', { name: 'Alerts', exact: true }).click();
    await page.getByLabel('Hostname', { exact: true }).fill(hostname);
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(page).toHaveURL(new RegExp('hostname=' + hostname));
    await expect(
      page.getByRole('link', { name: 'Windows account created', exact: true }),
    ).toHaveCount(1);
    await expect(
      page.getByRole('link', { name: 'Windows account created', exact: true }),
    ).toHaveAttribute('href', '/alerts/' + alertId);
    await page.getByRole('link', { name: 'Windows account created', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Supporting evidence' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Account Created', exact: true })).toBeVisible();
    await page.getByRole('combobox', { name: 'Status', exact: true }).selectOption('investigating');
    await page
      .getByRole('combobox', { name: 'Assigned analyst', exact: true })
      .selectOption(users[0].id);
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(
      page.getByRole('status').filter({ hasText: 'Investigation updated.' }),
    ).toBeVisible();
    await expect(page.getByRole('combobox', { name: 'Status', exact: true })).toHaveValue(
      'investigating',
    );
    await page
      .getByLabel('Add a note')
      .fill(
        'Synthetic frontend acceptance: reviewed account-creation evidence. No real account was created.',
      );
    await page.getByRole('button', { name: 'Add note', exact: true }).click();
    await expect(
      page.getByRole('status').filter({ hasText: 'Note added to the investigation.' }),
    ).toBeVisible();
    await expect(
      page.getByText(
        'Synthetic frontend acceptance: reviewed account-creation evidence. No real account was created.',
        { exact: true },
      ),
    ).toBeVisible();
    await page.screenshot({
      path: new URL('investigation-live.png', screenshots).pathname,
      fullPage: true,
    });
    const stored = await request<AlertRecord>('/alerts/' + alertId);
    expect(stored.status).toBe('investigating');
    expect(stored.assigned_to).toBe(users[0].id);
    expect(stored.note_count).toBe(1);
    const history = await request<{ items: unknown[] }>('/alerts/' + alertId + '/history');
    expect(history.items).toHaveLength(2);
    await page.getByRole('link', { name: hostname, exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Endpoint details' })).toBeVisible();
    await page.getByRole('navigation').getByRole('link', { name: 'Detection rules' }).click();
    await expect(page.getByText('Enabled in worker', { exact: true })).toHaveCount(6);
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
    await page.goto('/alerts/' + alertId);
    await signIn(users[1]);
    await expect(page.getByRole('heading', { name: 'Supporting evidence' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add note', exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
    expect(pageErrors).toEqual([]);
    await request('/alerts/' + alertId, 'PATCH', {
      expected_revision: stored.revision,
      status: 'resolved',
      assigned_to: null,
    });
    await writeFile(
      new URL('../../.local/frontend-live-result.json', import.meta.url),
      JSON.stringify(
        {
          status: 'passed',
          synthetic_endpoint: run,
          synthetic_alert: alertId,
          login: 'passed',
          dashboard: 'live backend data',
          investigation: 'assignment, status, note, evidence and history verified',
          viewer_permissions: 'read-only',
          rules: 6,
          logout: 'passed',
          browser_storage: 'no credentials',
          console_errors: 0,
        },
        null,
        2,
      ) + '\n',
    );
  } finally {
    // Each cleanup targets only this test's created users/endpoint. Existing telemetry is retained.
    const cleanup = await Promise.allSettled([
      ...users.map((user) =>
        request('/users/' + user.id, 'PATCH', { expected_revision: 0, active: false }),
      ),
      ...(enrolled
        ? [request('/endpoints/' + run, 'PATCH', { expected_revision: 0, active: false })]
        : []),
    ]);
    await request('/auth/logout', 'POST');
    if (cleanup.some((result) => result.status === 'rejected'))
      throw new Error('Live test cleanup needs review for this synthetic run: ' + run);
  }
});
