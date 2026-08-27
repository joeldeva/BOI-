import type { ApkAnalysisResult } from '../../types/api';
import { aggregateExperimentStatus } from '../../utils/analysisTruth.mjs';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState } from '../common/Atoms';

interface BehaviorAnalysisTabProps { result: ApkAnalysisResult; }

export function BehaviorAnalysisTab({ result }: BehaviorAnalysisTabProps) {
  const experiments = result.experiment_results ?? [];
  const runtime = result.runtime_evidence ?? [];
  const lineages = result.payload_lineage ?? [];
  const aggregate = aggregateExperimentStatus(experiments);
  const countSummary = Object.entries(aggregate.counts)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([status, count]) => `${status}: ${count}`)
    .join(' | ');

  if (experiments.length === 0 && runtime.length === 0 && lineages.length === 0) {
    return (
      <div>
        <h2 className="section-title">Behavior analysis</h2>
        <EmptyState title="No behavior analysis data" message="Dynamic analysis was not performed or runtime experiments were not executed for this sample." />
      </div>
    );
  }

  return (
    <div>
      <h2 className="section-title">Behavior analysis</h2>

      {experiments.length > 0 && (
        <>
          <h3 className="subsection-title">Experiment summary</h3>
          <div className="card padded">
            <table className="kv-table">
              <tbody>
                <tr><td>Experiments planned</td><td>{aggregate.total}</td></tr>
                <tr><td>Aggregate status</td><td><StatusPillAuto value={aggregate.status} /></td></tr>
                <tr><td>Status counts</td><td>{countSummary}</td></tr>
                <tr><td>Runtime findings</td><td>{runtime.length} structured events</td></tr>
              </tbody>
            </table>
          </div>

          <h3 className="subsection-title">Experiment results</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Experiment results">
              <thead><tr><th>Experiment ID</th><th>Type</th><th>Status</th><th>Summary</th></tr></thead>
              <tbody>
                {experiments.map(exp => (
                  <tr key={exp.experiment_id} className="no-hover">
                    <td className="hash">{exp.experiment_id}</td>
                    <td>{exp.experiment_type}</td>
                    <td><StatusPillAuto value={exp.status} /></td>
                    <td style={{ fontSize: 12 }}>{exp.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {lineages.length > 0 && (
        <>
          <h3 className="subsection-title">OTP and data lineage</h3>
          {lineages.map(lineage => (
            <div key={lineage.lineage_id} className="card padded" style={{ marginBottom: 14 }}>
              <table className="kv-table" style={{ marginBottom: 14 }}>
                <tbody>
                  <tr><td>Lineage</td><td className="hash">{lineage.lineage_id}</td></tr>
                  <tr><td>Proof level</td><td><StatusPillAuto value={lineage.trust_level} /></td></tr>
                  <tr>
                    <td>Complete exfiltration</td>
                    <td><StatusPillAuto value={lineage.is_complete_exfiltration ? 'YES' : 'NO'} /></td>
                  </tr>
                  <tr><td>Source evidence</td><td className="hash">{lineage.source_evidence_id}</td></tr>
                  <tr><td>Sink evidence</td><td className="hash">{lineage.sink_evidence_id ?? 'Not observed'}</td></tr>
                </tbody>
              </table>
              <div className="lineage" aria-label={`${lineage.lineage_id} source to sink evidence path`}>
                {lineage.steps.map((step, index) => (
                  <div key={`${lineage.lineage_id}-${step.step_index}`} style={{ display: 'contents' }}>
                    <div className={`lineage-node${step.phase === 'EGRESS' && lineage.is_complete_exfiltration ? ' proof' : ''}`}>
                      <strong>{step.phase}</strong>
                      <div>{step.evidence_id}<br />{step.transform_type}</div>
                    </div>
                    {index < lineage.steps.length - 1 && <div className="lineage-arrow">-&gt;</div>}
                  </div>
                ))}
              </div>
              <div style={{ fontSize: 12, color: '#777', marginTop: 12 }}>{lineage.summary}</div>
            </div>
          ))}
        </>
      )}

      {runtime.length > 0 && (
        <>
          <h3 className="subsection-title">Runtime timeline</h3>
          <div className="card padded">
            <div className="timeline">
              {runtime.map(ev => {
                const isProof = ev.trust_level === 'PAYLOAD_CORRELATED';
                return (
                  <div key={ev.evidence_id} className={`timeline-item${isProof ? ' proof' : ''}`}>
                    <div className="timeline-time">{`${(ev.timestamp_ms / 1000).toFixed(1)}s`}</div>
                    <div>
                      <div className="timeline-title">{ev.evidence_type}</div>
                      <div className="timeline-copy">{ev.description}</div>
                    </div>
                    {ev.trust_level && <StatusPillAuto value={ev.trust_level} />}
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
