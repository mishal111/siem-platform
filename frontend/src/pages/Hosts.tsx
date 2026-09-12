import { useState } from 'react';
import { Link, useParams } from 'react-router';
import { ArrowLeft, ArrowUpRight, Monitor } from 'lucide-react';
import { query } from '../api';
import { useRefresh, useResource } from '../hooks';
import {
  AlertTable,
  Details,
  Empty,
  ErrorState,
  EventTable,
  Heading,
  Loading,
  number,
  Pager,
  Panel,
  Refresh,
  time,
  zone,
} from '../components';
import type { Host, HostDetail, Page } from '../types';

export default function Hosts() {
  const [cursors, setCursors] = useState(['']);
  const [version, refresh] = useRefresh();
  const result = useResource<Page<Host>>(
    '/hosts' + query({ limit: 25, after: cursors.at(-1) }),
    version,
  );
  return (
    <>
      <Heading
        eyebrow="ENDPOINT VISIBILITY"
        title="Host inventory"
        description="The Windows and macOS endpoints that have reported to your SIEM."
      >
        <Refresh onClick={refresh} busy={result.loading} />
      </Heading>
      <div className="notice">
        Last contact reflects received telemetry. A quiet host is not necessarily offline.
      </div>
      <Panel
        title="Observed hosts"
        subtitle="Inventory is populated by incoming events or heartbeats."
      >
        {result.error ? (
          <ErrorState error={result.error} retry={refresh} />
        ) : !result.data ? (
          <Loading />
        ) : (
          <>
            {result.data.items.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>Operating system</th>
                      <th>Last contact</th>
                      <th>Heartbeat</th>
                      <th>Queue</th>
                      <th>
                        <span className="sr-only">Open host</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.data.items.map((host) => (
                      <tr key={host.endpoint_id}>
                        <td>
                          <Link
                            className="row-title host-link"
                            to={`/hosts/${encodeURIComponent(host.endpoint_id)}`}
                          >
                            <Monitor size={17} />
                            {host.hostname}
                          </Link>
                          <span className="cell-sub mono truncate-id">{host.endpoint_id}</span>
                        </td>
                        <td>{host.os === 'macos' ? 'macOS' : 'Windows'}</td>
                        <td className="nowrap">{time(host.last_seen_at)}</td>
                        <td>
                          {host.last_heartbeat_at ? time(host.last_heartbeat_at) : 'Not reported'}
                        </td>
                        <td>
                          {host.pending == null
                            ? 'Not reported'
                            : `${number(host.pending)} pending`}
                        </td>
                        <td>
                          <Link
                            className="icon-button"
                            to={`/hosts/${encodeURIComponent(host.endpoint_id)}`}
                            aria-label={`Open ${host.hostname}`}
                          >
                            <ArrowUpRight size={17} />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty
                title="No hosts have reported yet"
                text="Send telemetry from an endpoint collector to populate this inventory."
              />
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
        Times shown in {zone}. Periodic native collector heartbeats are not enabled yet.
      </p>
    </>
  );
}

export function HostPage() {
  const { id } = useParams();
  const [version, refresh] = useRefresh();
  const result = useResource<HostDetail>(`/hosts/${encodeURIComponent(id || '')}`, version);
  const data = result.data;
  return (
    <>
      <Link to="/hosts" className="back-link">
        <ArrowLeft size={15} />
        Host inventory
      </Link>
      <Heading
        title={data?.host.hostname || 'Host details'}
        description="Endpoint context and the latest activity received from this host."
      >
        <Refresh onClick={refresh} />
      </Heading>
      {result.error ? (
        <ErrorState error={result.error} retry={refresh} />
      ) : !data ? (
        <Loading />
      ) : (
        <>
          <Panel title="Endpoint details">
            <Details
              items={[
                ['Endpoint ID', data.host.endpoint_id],
                ['Operating system', data.host.os],
                ['First observed', time(data.host.first_seen_at)],
                ['Last contact', time(data.host.last_seen_at)],
                ['Last event received', time(data.host.last_event_received_at)],
                ['Last heartbeat', time(data.host.last_heartbeat_at)],
                ['Retained events', number(data.event_count)],
                ['Retained alerts', number(data.alert_count)],
                ['Collector version', data.host.collector_version || 'Not reported'],
                [
                  'Pending / rejected',
                  data.host.pending == null
                    ? 'Not reported'
                    : `${data.host.pending} / ${data.host.rejected ?? '—'}`,
                ],
              ]}
            />
            {data.host.source_error && (
              <p className="error-banner">Collector source error: {data.host.source_error}</p>
            )}
          </Panel>
          <Panel
            title="Recent alerts"
            action={
              <Link
                className="text-link"
                to={'/alerts' + query({ endpoint_id: data.host.endpoint_id })}
              >
                All host alerts
                <ArrowUpRight size={15} />
              </Link>
            }
          >
            <AlertTable items={data.recent_alerts} compact />
          </Panel>
          <Panel
            title="Recent events"
            action={
              <Link
                className="text-link"
                to={'/events' + query({ endpoint_id: data.host.endpoint_id })}
              >
                All host events
                <ArrowUpRight size={15} />
              </Link>
            }
          >
            <EventTable items={data.recent_events} />
          </Panel>
        </>
      )}
    </>
  );
}
