import { Link } from 'react-router';
import { ArrowUpRight, ShieldCheck } from 'lucide-react';
import { query } from '../api';
import { useRefresh, useResource } from '../hooks';
import { Badge, Empty, ErrorState, Heading, Loading, Panel, Refresh } from '../components';
import type { Rule } from '../types';

export default function Rules() {
  const [version, refresh] = useRefresh();
  const result = useResource<Rule[]>('/detections/rules', version);
  return (
    <>
      <Heading
        eyebrow="DETECTION COVERAGE"
        title="Detection rules"
        description="Understand what your SIEM looks for and why each detection matters."
      >
        <Refresh onClick={refresh} />
      </Heading>
      <div className="notice">
        These rules identify activity that warrants review. A match does not establish a compromise.
      </div>
      {result.error ? (
        <ErrorState error={result.error} retry={refresh} />
      ) : !result.data ? (
        <Loading />
      ) : result.data.length ? (
        <div className="rules-grid">
          {result.data.map((rule) => (
            <Panel key={rule.rule_id} className="rule-card">
              <div className="rule-top">
                <span className="small-icon">
                  <ShieldCheck size={20} />
                </span>
                <Badge value={rule.severity} />
              </div>
              <span className="eyebrow mono">
                {rule.rule_id} · V{rule.version}
              </span>
              <h2>{rule.name}</h2>
              <p>{rule.description}</p>
              <div className="rule-meta">
                <span>
                  {rule.mitre_technique} · {rule.mitre_name}
                </span>
                <span>
                  {rule.window_seconds
                    ? `${rule.threshold} events / ${rule.window_seconds / 60} min`
                    : 'Single-event detection'}
                </span>
                <span className={rule.enabled ? 'good' : 'muted'}>
                  {rule.enabled ? 'Enabled in worker' : 'Disabled'}
                </span>
              </div>
              <details>
                <summary>Matching requirements</summary>
                <pre className="raw-data">{JSON.stringify(rule.event_requirements, null, 2)}</pre>
              </details>
              <Link className="text-link" to={'/alerts' + query({ rule_id: rule.rule_id })}>
                Explore matching alerts
                <ArrowUpRight size={15} />
              </Link>
            </Panel>
          ))}
        </div>
      ) : (
        <Empty title="No rules available" />
      )}
    </>
  );
}
