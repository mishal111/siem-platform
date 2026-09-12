export type Role = 'viewer' | 'analyst' | 'admin';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive';
export interface User {
  id: string;
  username: string;
  role: Role;
  active: boolean;
  revision: number;
  created_at: string;
}
export interface Session {
  access_token: string;
  expires_at: string;
  user: User;
}
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}
export interface EventRecord {
  id: string;
  event_uid: string;
  endpoint_id: string;
  timestamp: string;
  received_at: string;
  hostname: string;
  os: string;
  source: string;
  event_type: string;
  event_code: number | null;
  username: string | null;
  user_domain: string | null;
  source_ip: string | null;
  severity: Severity;
  message: string;
  process_name?: string;
  command_line?: string;
  raw_event?: Record<string, unknown>;
}
export interface AlertRecord {
  id: string;
  rule_id: string;
  rule_name: string;
  rule_version: number;
  severity: Severity;
  status: AlertStatus;
  revision: number;
  assigned_to: string | null;
  updated_at: string | null;
  note_count: number;
  endpoint_id: string;
  hostname: string;
  os: string;
  username: string | null;
  source_ip: string | null;
  description: string;
  mitre_technique: string;
  mitre_name: string;
  event_count: number;
  created_at: string;
  first_seen: string;
  last_seen: string;
}
export interface Host {
  endpoint_id: string;
  hostname: string;
  os: string;
  first_seen_at: string;
  last_seen_at: string;
  last_heartbeat_at: string | null;
  last_event_received_at: string | null;
  collector_version: string | null;
  pending: number | null;
  rejected: number | null;
  source_error: string | null;
}
export interface HostDetail {
  host: Host;
  event_count: number;
  alert_count: number;
  recent_events: EventRecord[];
  recent_alerts: AlertRecord[];
}
export interface Summary {
  as_of: string;
  start_time: string;
  end_time: string;
  event_count: number;
  alert_count: number;
  events_by_type: Record<string, number>;
  events_by_os: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
  alerts_by_rule: Record<string, number>;
  recently_reporting_hosts: number;
  events_per_hour: { timestamp: string; count: number }[];
  top_hosts: { endpoint_id: string; count: number }[];
  top_source_ips: { source_ip: string; count: number }[];
}
export interface WorkerStatus {
  worker_recent: boolean;
  worker_last_seen_at: string | null;
  worker_last_error: string | null;
  events: Record<string, number>;
}
export interface Rule {
  rule_id: string;
  name: string;
  severity: Severity;
  enabled: boolean;
  description: string;
  mitre_technique: string;
  mitre_name: string;
  version: number;
  threshold: number;
  window_seconds: number;
  group_by: string[];
  event_requirements: Record<string, unknown>;
}
export interface Note {
  id: string;
  actor_id: string;
  text: string;
  created_at: string;
}
export interface History {
  id: string;
  actor_id: string;
  at: string;
  action: string;
  revision: number;
  changes: Record<string, unknown>;
}
export interface DirectoryUser {
  id: string;
  username: string;
  role: Role;
}
