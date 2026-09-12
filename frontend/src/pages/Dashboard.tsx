import { Link } from 'react-router';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Activity, ArrowUpRight, CircleAlert, Monitor, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { useRefresh, useResource } from '../hooks';
import {
  AlertTable,
  Badge,
  Empty,
  ErrorState,
  Heading,
  Loading,
  number,
  Panel,
  Refresh,
  time,
  zone,
} from '../components';
import type { AlertRecord, Page, Summary, WorkerStatus } from '../types';

export default function Dashboard() {
  const [hours, setHours] = useState(24);
  const [version, refresh] = useRefresh(30000);
  const result = useResource<Summary>(`/dashboard/summary?hours=${hours}`, version);
  const recent = useResource<Page<AlertRecord>>('/alerts?limit=6', version);
  const worker = useResource<WorkerStatus>('/detections/status', version);
  const data = result.data;
  return (
    <>
      <Heading
        eyebrow="YOUR ENVIRONMENT, AT A GLANCE"
        title="Security overview"
        description="A clear picture of your telemetry and the activity that needs attention."
      >
        <label className="sr-only" htmlFor="dashboard-period">
          Overview period
        </label>
        <select
          id="dashboard-period"
          value={hours}
          onChange={(event) => setHours(Number(event.target.value))}
        >
          <option value={24}>Last 24 hours</option>
          <option value={48}>Last 48 hours</option>
          <option value={168}>Last 7 days</option>
        </select>
        <Refresh onClick={refresh} busy={result.loading} />
      </Heading>
      {result.error ? (
        <ErrorState error={result.error} retry={refresh} />
      ) : !data ? (
        <Loading />
      ) : (
        <>
          <div className="stats-grid">
            {[
              {
                title: 'Events received',
                value: data.event_count,
                icon: Activity,
                detail: `Across the last ${hours} hours`,
                style: 'purple',
              },
              {
                title: 'Alerts generated',
                value: data.alert_count,
                icon: ShieldCheck,
                detail: `${number(data.alerts_by_severity.critical || 0)} critical in this period`,
                style: 'orange',
              },
              {
                title: 'Needs review',
                value:
                  (data.alerts_by_status.open || 0) + (data.alerts_by_status.investigating || 0),
                icon: CircleAlert,
                detail: 'Open or investigating · this period',
                style: 'red',
              },
              {
                title: 'Reporting hosts',
                value: data.recently_reporting_hosts,
                icon: Monitor,
                detail: 'Contact within the last 5 minutes',
                style: 'green',
              },
            ].map((stat) => (
              <section className="stat-card" key={stat.title}>
                <div className="stat-top">
                  <span>{stat.title}</span>
                  <span className={`stat-icon ${stat.style}`}>
                    <stat.icon size={18} />
                  </span>
                </div>
                <strong>{number(stat.value)}</strong>
                <p>{stat.detail}</p>
              </section>
            ))}
          </div>
          <div className="overview-charts">
            <Panel
              title="Event activity"
              subtitle="Incoming telemetry over time"
              action={
                <span className="chart-key">
                  <i />
                  Events / hour
                </span>
              }
            >
              <div
                className="activity-chart"
                role="img"
                aria-label={`${number(data.event_count)} events received in the last ${hours} hours. Hourly breakdown follows.`}
              >
                <ResponsiveContainer width="100%" height={230}>
                  <AreaChart
                    data={data.events_per_hour}
                    margin={{ top: 12, right: 20, left: -15, bottom: 4 }}
                  >
                    <defs>
                      <linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#8670df" stopOpacity={0.23} />
                        <stop offset="100%" stopColor="#8670df" stopOpacity={0.01} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 4" vertical={false} stroke="#ececf1" />
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={(value) =>
                        new Date(value).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })
                      }
                      minTickGap={48}
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 11, fill: '#868795' }}
                    />
                    <YAxis
                      allowDecimals={false}
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 11, fill: '#868795' }}
                    />
                    <Tooltip
                      labelFormatter={(value) => time(String(value))}
                      contentStyle={{ borderRadius: 10, borderColor: '#e7e7ee', fontSize: 12 }}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      name="Events"
                      stroke="#8973df"
                      strokeWidth={2.5}
                      fill="url(#eventFill)"
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <details className="chart-data">
                <summary>
                  View hourly counts <span>· {zone}</span>
                </summary>
                <div className="chart-counts">
                  {data.events_per_hour.map((hour) => (
                    <div key={hour.timestamp}>
                      <span>{time(hour.timestamp)}</span>
                      <strong>{number(hour.count)}</strong>
                    </div>
                  ))}
                </div>
              </details>
            </Panel>
            <Panel title="Alert severity" subtitle="Alerts created in the selected period">
              <div className="severity-total">
                <strong>{number(data.alert_count)}</strong>
                <span>total alerts</span>
              </div>
              <div className="severity-bars">
                {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
                  <div className="severity-row" key={severity}>
                    <Badge value={severity} />
                    <div className="bar-track">
                      <span
                        className={`bar-${severity}`}
                        style={{
                          width: `${data.alert_count ? ((data.alerts_by_severity[severity] || 0) / data.alert_count) * 100 : 0}%`,
                        }}
                      />
                    </div>
                    <strong>{number(data.alerts_by_severity[severity] || 0)}</strong>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        </>
      )}
      <Panel
        title="Recent alerts"
        subtitle="Latest detections across all retained activity"
        action={
          <Link className="text-link" to="/alerts">
            View all alerts
            <ArrowUpRight size={15} />
          </Link>
        }
      >
        {recent.error ? (
          <ErrorState error={recent.error} retry={refresh} />
        ) : recent.data ? (
          <AlertTable items={recent.data.items} compact />
        ) : (
          <Loading text="Loading recent alerts…" />
        )}
      </Panel>
      <div className="overview-bottom">
        <Panel title="Telemetry sources" subtitle="Event distribution in the selected period">
          {data ? (
            <div className="source-list">
              {Object.entries(data.events_by_os).length ? (
                Object.entries(data.events_by_os).map(([os, count]) => (
                  <div key={os}>
                    <span className="source-icon">
                      <Monitor size={20} />
                    </span>
                    <div>
                      <strong>{os === 'macos' ? 'macOS' : 'Windows'}</strong>
                      <span className="cell-sub">Endpoint telemetry</span>
                    </div>
                    <b>
                      {number(count)}
                      <span className="cell-sub">events</span>
                    </b>
                  </div>
                ))
              ) : (
                <Empty
                  title="Awaiting telemetry"
                  text="Connected collectors will appear as they report events."
                />
              )}
            </div>
          ) : (
            <p className="panel-note">Telemetry summary is unavailable.</p>
          )}
        </Panel>
        <Panel
          title="Detection pipeline"
          subtitle="Current processing state, across all retained events"
          action={
            <Link className="text-link" to="/rules">
              View rules
              <ArrowUpRight size={15} />
            </Link>
          }
        >
          {worker.error ? (
            <ErrorState error={worker.error} retry={refresh} />
          ) : worker.data ? (
            <div className="pipeline">
              <div className={`pipeline-state ${worker.data.worker_recent ? 'good' : 'warning'}`}>
                <span className="status-dot" />
                {worker.data.worker_recent ? 'Worker is reporting' : 'Worker contact is stale'}
              </div>
              <div className="pipeline-counts">
                <span>
                  <strong>{number(worker.data.events.pending || 0)}</strong>Pending
                </span>
                <span>
                  <strong>{number(worker.data.events.processed || 0)}</strong>Processed
                </span>
                <span>
                  <strong>{number(worker.data.events.failed || 0)}</strong>Failed
                </span>
              </div>
              <p>Last contact: {time(worker.data.worker_last_seen_at)}</p>
              {worker.data.worker_last_error && (
                <p className="error-banner">Worker reported: {worker.data.worker_last_error}</p>
              )}
            </div>
          ) : (
            <Loading />
          )}
        </Panel>
      </div>
      <div className="view-footnote">
        {data ? `Updated ${time(data.as_of)}. ` : ''}Refreshes every 30 seconds while visible. Event
        charts use receipt time; alert charts use creation time.
      </div>
    </>
  );
}
