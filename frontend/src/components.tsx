import type { ReactNode } from 'react';
import { Link } from 'react-router';
import {
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Inbox,
  LoaderCircle,
  RefreshCw,
} from 'lucide-react';
import type { AlertRecord, EventRecord } from './types';

export const label = (value: string) =>
  value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
export const number = (value: number) => new Intl.NumberFormat().format(value);
export function time(value?: string | null) {
  return value
    ? new Date(value).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : 'Not reported';
}
export const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
export function Badge({ value }: { value: string }) {
  return (
    <span className={`badge badge-${value}`}>
      <i />
      {label(value)}
    </span>
  );
}
export function Heading({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="heading-actions">{children}</div>
    </div>
  );
}
export function Refresh({ onClick, busy = false }: { onClick: () => void; busy?: boolean }) {
  return (
    <button className="button" onClick={onClick} disabled={busy}>
      <RefreshCw size={15} className={busy ? 'spin' : ''} />
      Refresh
    </button>
  );
}
export function Loading({ text = 'Loading your workspace…' }: { text?: string }) {
  return (
    <div className="loading-state" role="status">
      <LoaderCircle size={23} className="spin" />
      {text}
    </div>
  );
}
export function ErrorState({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={24} />
      <h3>We couldn’t load this view</h3>
      <p>{error.message}</p>
      <button className="button" onClick={retry}>
        Try again
      </button>
    </div>
  );
}
export function Empty({
  title = 'Nothing here yet',
  text = 'New activity will appear here when it is received.',
}: {
  title?: string;
  text?: string;
}) {
  return (
    <div className="empty-state">
      <Inbox size={28} strokeWidth={1.4} />
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
export function Panel({
  title,
  subtitle,
  action,
  children,
  className = '',
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <div className="panel-heading">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
export function Pager({
  next,
  previous,
  count,
  page,
}: {
  next?: () => void;
  previous?: () => void;
  count: number;
  page: number;
}) {
  return (
    <div className="pager">
      <span>
        {number(count)} results on page {page}
      </span>
      <div>
        <button className="button compact" onClick={previous} disabled={!previous}>
          <ChevronLeft size={15} />
          Previous
        </button>
        <button className="button compact" onClick={next} disabled={!next}>
          Next
          <ChevronRight size={15} />
        </button>
      </div>
    </div>
  );
}
export function Details({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="details">
      {items.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}
export function AlertTable({
  items,
  compact = false,
}: {
  items: AlertRecord[];
  compact?: boolean;
}) {
  if (!items.length)
    return (
      <Empty
        title="No alerts found"
        text="Try a broader filter, or wait for a detection to match incoming activity."
      />
    );
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Detection</th>
            <th>Severity</th>
            <th>Host</th>
            <th>Status</th>
            {!compact && <th>Created</th>}
            <th>
              <span className="sr-only">Open alert</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <Link className="row-title" to={`/alerts/${item.id}`}>
                  {item.rule_name}
                </Link>
                <span className="cell-sub mono">
                  {item.rule_id} <span className="text-dot">·</span> {item.mitre_technique}
                </span>
              </td>
              <td>
                <Badge value={item.severity} />
              </td>
              <td>
                <Link to={`/hosts/${encodeURIComponent(item.endpoint_id)}`} className="host-name">
                  {item.hostname}
                </Link>
                <span className="cell-sub">{item.os === 'macos' ? 'macOS' : 'Windows'}</span>
              </td>
              <td>
                <Badge value={item.status} />
              </td>
              {!compact && <td className="nowrap muted">{time(item.created_at)}</td>}
              <td>
                <Link
                  className="icon-button"
                  to={`/alerts/${item.id}`}
                  aria-label={`Investigate ${item.rule_name}`}
                >
                  <ChevronRight size={17} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function EventTable({ items }: { items: EventRecord[] }) {
  if (!items.length)
    return (
      <Empty
        title="No events found"
        text="Try a broader filter or check that your collectors are sending telemetry."
      />
    );
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Event</th>
            <th>Severity</th>
            <th>Host / user</th>
            <th>Source IP</th>
            <th>Event time</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <Link className="row-title" to={`/events/${item.id}`}>
                  {label(item.event_type)}
                </Link>
                <span className="cell-sub">
                  {item.source}
                  {item.event_code != null && ` · ${item.event_code}`}
                </span>
              </td>
              <td>
                <Badge value={item.severity} />
              </td>
              <td>
                <span className="row-title">{item.hostname}</span>
                <span className="cell-sub">{item.username || 'No user reported'}</span>
              </td>
              <td className="mono muted">{item.source_ip || '—'}</td>
              <td className="nowrap muted">{time(item.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
