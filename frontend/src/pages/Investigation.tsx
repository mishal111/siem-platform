import { useRef, useState } from 'react';
import { Link, useParams } from 'react-router';
import { ArrowLeft, FileText, History as HistoryIcon, Save, Send } from 'lucide-react';
import { api, ApiError, post, query } from '../api';
import { useAuth } from '../auth';
import { useRefresh, useResource } from '../hooks';
import {
  Badge,
  Details,
  Empty,
  ErrorState,
  EventTable,
  Heading,
  label,
  Loading,
  Panel,
  Refresh,
  time,
} from '../components';
import type { AlertRecord, DirectoryUser, EventRecord, History, Note, Page } from '../types';

export default function Investigation() {
  const { id } = useParams();
  return <InvestigationView key={id} id={id || ''} />;
}

function InvestigationView({ id }: { id: string }) {
  const { session } = useAuth();
  const editor = session.user.role !== 'viewer';
  const path = `/alerts/${encodeURIComponent(id)}`;
  const [version, refresh] = useRefresh();
  const alert = useResource<AlertRecord>(path, version);
  const evidence = useResource<{ items: EventRecord[]; missing_event_ids: string[] }>(
    path + '/events',
    version,
  );
  const notes = useResource<Note[]>(path + '/notes', version);
  const [historyCursor, setHistoryCursor] = useState(0);
  const history = useResource<{ items: History[]; next_revision: number | null }>(
    path + `/history?limit=50&after_revision=${historyCursor}`,
    version,
  );
  const [directoryCursor, setDirectoryCursor] = useState('');
  const directory = useResource<Page<DirectoryUser>>(
    '/users/directory' + query({ limit: 100, after: directoryCursor }),
  );
  const [knownUsers, setKnownUsers] = useState<DirectoryUser[]>([]);
  const users = [...knownUsers, ...(directory.data?.items || [])];
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [text, setText] = useState('');
  // Preserve a note UUID after an ambiguous network failure so retry cannot create a duplicate.
  const pendingNote = useRef<{ text: string; note_id: string } | null>(null);
  const [blocked, setBlocked] = useState(false);
  function reload() {
    setBlocked(false);
    setError('');
    setHistoryCursor(0);
    refresh();
  }
  const actor = (id: string) =>
    id === session.user.id
      ? session.user.username
      : users.find((user) => user.id === id)?.username || id;
  async function mutate(action: () => Promise<unknown>, message: string, after?: () => void) {
    if (busy || blocked) return;
    setBusy(true);
    setError('');
    setSuccess('');
    try {
      await action();
      after?.();
      setSuccess(message);
      setHistoryCursor(0);
      refresh();
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        setBlocked(true);
        setError(
          'This alert changed, or the requested edit conflicts with its current state. Reload the alert, review it, then submit your intended edit again. Your draft note is kept.',
        );
      } else setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const data = alert.data;
  return (
    <>
      <Link className="back-link" to="/alerts">
        <ArrowLeft size={15} />
        Alert queue
      </Link>
      <Heading
        eyebrow="ALERT INVESTIGATION"
        title={data?.rule_name || 'Investigation'}
        description={
          data
            ? `${data.rule_id} · ${data.hostname}`
            : 'Load the detection and its supporting evidence.'
        }
      >
        <Refresh onClick={reload} busy={alert.loading || busy} />
      </Heading>
      {error && (
        <div className="error-banner" role="alert">
          {error}
          {blocked && (
            <button className="button compact" onClick={reload}>
              Reload alert
            </button>
          )}
        </div>
      )}
      {success && (
        <p className="success-banner" role="status">
          {success}
        </p>
      )}
      {alert.error ? (
        <ErrorState error={alert.error} retry={reload} />
      ) : !data ? (
        <Loading />
      ) : (
        <>
          <div className="investigation-grid">
            <div>
              <Panel title="Detection summary" action={<Badge value={data.severity} />}>
                <p className="description-block">{data.description}</p>
                <Details
                  items={[
                    ['Status', <Badge value={data.status} />],
                    ['MITRE ATT&CK', `${data.mitre_technique} · ${data.mitre_name}`],
                    [
                      'Host',
                      <Link to={`/hosts/${encodeURIComponent(data.endpoint_id)}`}>
                        {data.hostname}
                      </Link>,
                    ],
                    ['User', data.username],
                    ['Source IP', data.source_ip],
                    [
                      'Evidence',
                      `${data.event_count} ${data.event_count === 1 ? 'event' : 'events'}`,
                    ],
                    ['First event', time(data.first_seen)],
                    ['Last event', time(data.last_seen)],
                    ['Alert created', time(data.created_at)],
                    ['Assigned to', data.assigned_to ? actor(data.assigned_to) : 'Unassigned'],
                  ]}
                />
              </Panel>
            </div>
            <Panel
              title="Investigation status"
              subtitle={
                editor
                  ? 'Keep the review state and ownership up to date.'
                  : 'Your viewer role provides read-only access.'
              }
            >
              <form
                className="workflow-form"
                key={data.revision}
                onSubmit={(event) => {
                  event.preventDefault();
                  const fields = new FormData(event.currentTarget);
                  const body: Record<string, unknown> = {
                    expected_revision: data.revision,
                    status: fields.get('status'),
                  };
                  if (!directory.error && directory.data)
                    body.assigned_to = fields.get('assigned_to') || null;
                  void mutate(
                    () => api(path, { method: 'PATCH', body: JSON.stringify(body) }),
                    'Investigation updated.',
                  );
                }}
              >
                <fieldset disabled={!editor || busy || blocked}>
                  <label>
                    Status
                    <select name="status" defaultValue={data.status}>
                      {['open', 'investigating', 'resolved', 'false_positive'].map((value) => (
                        <option key={value} value={value}>
                          {label(value)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Assigned analyst
                    <select
                      name="assigned_to"
                      defaultValue={data.assigned_to || ''}
                      disabled={!directory.data || !!directory.error}
                    >
                      <option value="">Unassigned</option>
                      {data.assigned_to && !users.some((user) => user.id === data.assigned_to) && (
                        <option value={data.assigned_to}>
                          {actor(data.assigned_to)} (current assignment)
                        </option>
                      )}
                      {users.map((user) => (
                        <option key={user.id} value={user.id}>
                          {user.username} · {user.role}
                        </option>
                      ))}
                    </select>
                  </label>
                  {editor && (
                    <button className="button primary" type="submit">
                      <Save size={15} />
                      {busy ? 'Saving…' : 'Save changes'}
                    </button>
                  )}
                </fieldset>
                {directory.error && (
                  <p className="muted">
                    The assignment directory is unavailable. Existing assignment is preserved.
                  </p>
                )}
                {directory.data?.next_cursor && (
                  <button
                    type="button"
                    className="text-link"
                    onClick={() => {
                      setKnownUsers(users);
                      setDirectoryCursor(directory.data!.next_cursor!);
                    }}
                  >
                    Load more analysts
                  </button>
                )}
              </form>
              <p className="panel-note">
                Revision {data.revision}. Changes are recorded in the audit history.
              </p>
            </Panel>
          </div>
          <Panel title="Supporting evidence" subtitle="The original events used by this detection.">
            {evidence.error ? (
              <ErrorState error={evidence.error} retry={reload} />
            ) : evidence.data ? (
              <>
                {evidence.data.missing_event_ids.length > 0 && (
                  <p className="error-banner">
                    {evidence.data.missing_event_ids.length} evidence records are unavailable. This
                    investigation has incomplete evidence.
                  </p>
                )}
                <EventTable items={evidence.data.items} />
              </>
            ) : (
              <Loading />
            )}
          </Panel>
          <div className="investigation-grid">
            <Panel title="Investigation notes" action={<FileText size={18} className="muted" />}>
              {notes.error ? (
                <ErrorState error={notes.error} retry={reload} />
              ) : !notes.data ? (
                <Loading />
              ) : notes.data.length ? (
                <div className="notes-list">
                  {notes.data.map((note) => (
                    <article key={note.id}>
                      <div>
                        <strong>{actor(note.actor_id)}</strong>
                        <time>{time(note.created_at)}</time>
                      </div>
                      <p>{note.text}</p>
                    </article>
                  ))}
                </div>
              ) : (
                <Empty
                  title="Start the investigation story"
                  text="Record what you reviewed and what you found."
                />
              )}
              {editor && (
                <form
                  className="note-form"
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (!text.trim()) return;
                    if (!pendingNote.current || pendingNote.current.text !== text)
                      pendingNote.current = { text, note_id: crypto.randomUUID() };
                    const note = pendingNote.current;
                    void mutate(
                      () => post(path + '/notes', { ...note, expected_revision: data.revision }),
                      'Note added to the investigation.',
                      () => {
                        setText('');
                        pendingNote.current = null;
                      },
                    );
                  }}
                >
                  <label>
                    Add a note
                    <textarea
                      required
                      disabled={busy}
                      minLength={1}
                      maxLength={4000}
                      value={text}
                      onChange={(event) => setText(event.target.value)}
                      placeholder="What did you observe? Include evidence and next actions."
                      rows={4}
                    />
                  </label>
                  <div>
                    <span>{text.length} / 4,000</span>
                    <button
                      className="button primary"
                      disabled={busy || blocked || !text.trim() || data.note_count >= 100}
                    >
                      <Send size={14} />
                      Add note
                    </button>
                  </div>
                  {data.note_count >= 100 && (
                    <p className="muted">This alert has reached its 100-note limit.</p>
                  )}
                </form>
              )}
            </Panel>
            <Panel
              title="Audit history"
              subtitle="Attributable changes, in revision order"
              action={<HistoryIcon size={18} className="muted" />}
            >
              {history.error ? (
                <ErrorState error={history.error} retry={reload} />
              ) : !history.data ? (
                <Loading />
              ) : (
                <>
                  {history.data.items.length ? (
                    <ol className="history-list">
                      {history.data.items.map((entry) => (
                        <li key={entry.id}>
                          <span className="history-dot" />
                          <strong>{label(entry.action)}</strong>
                          <p>
                            {actor(entry.actor_id)} · revision {entry.revision}
                          </p>
                          <time>{time(entry.at)}</time>
                          <dl className="history-changes">
                            {Object.entries(entry.changes).map(([field, value]) => (
                              <div key={field}>
                                <dt>
                                  {field === 'assigned_to'
                                    ? 'Assigned to'
                                    : field === 'note_id'
                                      ? 'Note'
                                      : label(field)}
                                </dt>
                                <dd>
                                  {field === 'assigned_to'
                                    ? value
                                      ? actor(String(value))
                                      : 'Unassigned'
                                    : field === 'status'
                                      ? label(String(value))
                                      : field === 'note_id'
                                        ? 'Added to this investigation'
                                        : String(value ?? '—')}
                                </dd>
                              </div>
                            ))}
                          </dl>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <Empty
                      title="No changes yet"
                      text="Status changes, assignments, and notes will be recorded here."
                    />
                  )}
                  <div className="history-pages">
                    {historyCursor > 0 && (
                      <button className="button compact" onClick={() => setHistoryCursor(0)}>
                        First changes
                      </button>
                    )}
                    {history.data.next_revision && (
                      <button
                        className="button compact"
                        onClick={() => setHistoryCursor(history.data!.next_revision!)}
                      >
                        Next changes
                      </button>
                    )}
                  </div>
                </>
              )}
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
