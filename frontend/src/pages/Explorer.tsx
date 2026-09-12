import { useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router';
import { ArrowLeft, Search, SlidersHorizontal } from 'lucide-react';
import { query } from '../api';
import { useRefresh, useResource } from '../hooks';
import {
  AlertTable,
  Badge,
  Details,
  ErrorState,
  EventTable,
  Heading,
  label,
  Loading,
  Pager,
  Panel,
  Refresh,
  time,
  zone,
} from '../components';
import type { AlertRecord, EventRecord, Page } from '../types';

const types = [
  'login_success',
  'login_failure',
  'logout',
  'account_created',
  'account_deleted',
  'group_membership_changed',
  'privilege_assigned',
  'process_created',
  'service_installed',
  'security_log_cleared',
  'ssh_login',
  'sudo_execution',
  'firewall_event',
  'security_tool_event',
  'other',
];
function localTime(value: string | null) {
  if (!value || Number.isNaN(Date.parse(value))) return '';
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export default function Explorer({ kind }: { kind: 'events' | 'alerts' }) {
  const [params, setParams] = useSearchParams();
  return (
    <ExplorerView key={kind + params.toString()} kind={kind} params={params} onFilter={setParams} />
  );
}

function ExplorerView({
  kind,
  params,
  onFilter,
}: {
  kind: 'events' | 'alerts';
  params: URLSearchParams;
  onFilter: (params: URLSearchParams) => void;
}) {
  const alerts = kind === 'alerts';
  const [cursors, setCursors] = useState<string[]>(['']);
  const [version, refresh] = useRefresh();
  const [error, setError] = useState('');
  const fields = [
    'hostname',
    'endpoint_id',
    'severity',
    'start_time',
    'end_time',
    ...(alerts
      ? ['status', 'rule_id', 'assigned_to', 'mitre_technique']
      : ['os', 'event_type', 'event_code', 'username', 'source_ip']),
  ];
  const filters = Object.fromEntries(fields.map((field) => [field, params.get(field)]));
  const result = useResource<Page<AlertRecord | EventRecord>>(
    `/${kind}${query({ ...filters, limit: 25, cursor: cursors.at(-1) })}`,
    version,
  );
  const hasFilters = fields.some((field) => params.get(field));
  return (
    <>
      <Heading
        eyebrow={alerts ? 'DETECT & INVESTIGATE' : 'EXPLORE YOUR TELEMETRY'}
        title={alerts ? 'Alert queue' : 'Event explorer'}
        description={
          alerts
            ? 'Review detections, follow the evidence, and track each investigation.'
            : 'Search normalized security activity from Windows and macOS endpoints.'
        }
      >
        <Refresh onClick={refresh} busy={result.loading} />
      </Heading>
      <Panel className="filter-panel">
        <form
          key={params.toString()}
          onSubmit={(event) => {
            event.preventDefault();
            setError('');
            const data = new FormData(event.currentTarget);
            const next = new URLSearchParams();
            for (const field of fields) {
              const value = String(data.get(field) || '').trim();
              if (value)
                next.set(field, field.endsWith('_time') ? new Date(value).toISOString() : value);
            }
            if (
              next.get('start_time') &&
              next.get('end_time') &&
              new Date(next.get('start_time')!) > new Date(next.get('end_time')!)
            ) {
              setError('Start time must be before end time.');
              return;
            }
            onFilter(next);
          }}
        >
          <div className="filter-top">
            <span>
              <SlidersHorizontal size={16} /> Filter {kind}
            </span>
            {hasFilters && (
              <button
                type="button"
                className="text-link"
                onClick={() => onFilter(new URLSearchParams())}
              >
                Clear filters
              </button>
            )}
          </div>
          <div className="filters">
            <label>
              Hostname
              <input
                name="hostname"
                defaultValue={params.get('hostname') || ''}
                maxLength={255}
                placeholder="Exact hostname"
              />
            </label>
            <label>
              Severity
              <select name="severity" defaultValue={params.get('severity') || ''}>
                <option value="">All severities</option>
                {['critical', 'high', 'medium', 'low', 'info'].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            {alerts ? (
              <label>
                Status
                <select name="status" defaultValue={params.get('status') || ''}>
                  <option value="">All statuses</option>
                  {['open', 'investigating', 'resolved', 'false_positive'].map((value) => (
                    <option key={value} value={value}>
                      {label(value)}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <label>
                Operating system
                <select name="os" defaultValue={params.get('os') || ''}>
                  <option value="">All systems</option>
                  <option value="windows">Windows</option>
                  <option value="macos">macOS</option>
                </select>
              </label>
            )}
            {alerts ? (
              <label>
                Rule ID
                <input
                  name="rule_id"
                  defaultValue={params.get('rule_id') || ''}
                  placeholder="e.g. AUTH-BRUTE-001"
                  maxLength={255}
                />
              </label>
            ) : (
              <label>
                Event type
                <select name="event_type" defaultValue={params.get('event_type') || ''}>
                  <option value="">All event types</option>
                  {types.map((value) => (
                    <option key={value} value={value}>
                      {label(value)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <button className="button primary filter-submit">
              <Search size={15} />
              Apply filters
            </button>
          </div>
          <details
            className="advanced-filters"
            open={
              [
                'endpoint_id',
                'start_time',
                'end_time',
                'username',
                'source_ip',
                'event_code',
                'assigned_to',
                'mitre_technique',
              ].some((key) => !!params.get(key)) || undefined
            }
          >
            <summary>
              More filters <span>· exact matches · times in {zone}</span>
            </summary>
            <div className="filters advanced">
              <label>
                Endpoint ID
                <input
                  name="endpoint_id"
                  defaultValue={params.get('endpoint_id') || ''}
                  maxLength={255}
                />
              </label>
              {alerts ? (
                <>
                  <label>
                    Assigned user ID
                    <input
                      name="assigned_to"
                      defaultValue={params.get('assigned_to') || ''}
                      maxLength={255}
                    />
                  </label>
                  <label>
                    MITRE technique
                    <input
                      name="mitre_technique"
                      defaultValue={params.get('mitre_technique') || ''}
                      maxLength={255}
                      placeholder="e.g. T1110"
                    />
                  </label>
                </>
              ) : (
                <>
                  <label>
                    Username
                    <input
                      name="username"
                      defaultValue={params.get('username') || ''}
                      maxLength={255}
                    />
                  </label>
                  <label>
                    Source IP
                    <input
                      name="source_ip"
                      defaultValue={params.get('source_ip') || ''}
                      maxLength={45}
                    />
                  </label>
                  <label>
                    Event code
                    <input
                      name="event_code"
                      defaultValue={params.get('event_code') || ''}
                      inputMode="numeric"
                      pattern="[0-9]+"
                      maxLength={19}
                    />
                  </label>
                </>
              )}
              <label>
                From
                <input
                  type="datetime-local"
                  name="start_time"
                  defaultValue={localTime(params.get('start_time'))}
                />
              </label>
              <label>
                Until
                <input
                  type="datetime-local"
                  name="end_time"
                  defaultValue={localTime(params.get('end_time'))}
                />
              </label>
            </div>
          </details>
          {error && (
            <p className="error-banner" role="alert">
              {error}
            </p>
          )}
        </form>
      </Panel>
      <Panel
        title={alerts ? 'Detection results' : 'Security events'}
        subtitle={
          alerts
            ? 'Newest alerts first · filtered by creation time'
            : 'Newest events first · filtered by source event time'
        }
      >
        {result.error ? (
          <ErrorState error={result.error} retry={refresh} />
        ) : !result.data ? (
          <Loading />
        ) : (
          <>
            {alerts ? (
              <AlertTable items={result.data.items as AlertRecord[]} />
            ) : (
              <EventTable items={result.data.items as EventRecord[]} />
            )}
            <Pager
              count={result.data.items.length}
              page={cursors.length}
              previous={
                cursors.length > 1 ? () => setCursors((value) => value.slice(0, -1)) : undefined
              }
              next={
                result.data.next_cursor
                  ? () => setCursors((value) => [...value, result.data!.next_cursor!])
                  : undefined
              }
            />
          </>
        )}
      </Panel>
      <p className="view-footnote">
        Timestamps displayed in {zone}. Filters match exact values and apply across all stored
        results.
      </p>
    </>
  );
}

export function EventDetail() {
  const { id } = useParams();
  const [version, refresh] = useRefresh();
  const result = useResource<EventRecord>(`/events/${encodeURIComponent(id || '')}`, version);
  const data = result.data;
  return (
    <>
      <Link to="/events" className="back-link">
        <ArrowLeft size={15} />
        Event explorer
      </Link>
      <Heading
        title="Event details"
        description="The normalized record and original telemetry, together."
      >
        <Refresh onClick={refresh} />
      </Heading>
      {result.error ? (
        <ErrorState error={result.error} retry={refresh} />
      ) : !data ? (
        <Loading />
      ) : (
        <>
          <Panel
            title={label(data.event_type)}
            subtitle={data.message}
            action={<Badge value={data.severity} />}
          >
            <Details
              items={[
                [
                  'Host',
                  <Link to={`/hosts/${encodeURIComponent(data.endpoint_id)}`}>
                    {data.hostname}
                  </Link>,
                ],
                ['Operating system', data.os],
                ['Source', data.source],
                ['Event code', data.event_code],
                ['User', data.username],
                ['Source IP', data.source_ip],
                ['Event time', time(data.timestamp)],
                ['Received', time(data.received_at)],
                ['Process', data.process_name],
                ['Endpoint ID', data.endpoint_id],
                ['Event UID', data.event_uid],
                ['Record ID', data.id],
              ]}
            />
          </Panel>
          {data.command_line && (
            <Panel title="Command line">
              <pre className="raw-data">{data.command_line}</pre>
            </Panel>
          )}
          <Panel
            title="Full event record"
            subtitle="Read-only source data; displayed as plain text."
          >
            <pre className="raw-data">{JSON.stringify(data, null, 2)}</pre>
          </Panel>
        </>
      )}
    </>
  );
}
