import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState } from '../common/Atoms';

interface BehaviorAnalysisTabProps { result: ApkAnalysisResult; }

export function BehaviorAnalysisTab({ result }: BehaviorAnalysisTabProps) {
  const experiments = result.experiment_results ?? [];
  const runtime = result.runtime_evidence ?? [];

  const proofEvents = runtime.filter(e => e.trust_level === 'PAYLOAD_CORRELATED');
  const hasProof = proofEvents.length > 0;

  if (experiments.length === 0 && runtime.length === 0) {
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
                <tr><td>Experiments executed</td><td>{experiments.length}</td></tr>
                <tr><td>Status</td><td><StatusPillAuto value="COMPLETED" /></td></tr>
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

      {runtime.length > 0 && (
        <>
          <h3 className="subsection-title">Runtime timeline</h3>
          <div className="card padded">
            <div className="timeline">
              {runtime.map((ev, i) => {
                const isProof = ev.trust_level === 'PAYLOAD_CORRELATED';
                return (
                  <div key={i} className={`timeline-item${isProof ? ' proof' : ''}`}>
                    <div className="timeline-time">{ev.timestamp_ms ? `${(ev.timestamp_ms / 1000).toFixed(1)}s` : '—'}</div>
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

      {hasProof && (
        <>
          <h3 className="subsection-title">OTP lineage proof</h3>
          <div className="card padded">
            <div className="lineage">
              {proofEvents.map((ev, i, arr) => (
                <div key={ev.evidence_id} style={{ display: 'contents' }}>
                  <div className={`lineage-node${i === arr.length - 1 ? ' proof' : ''}`}>
                    <strong>{ev.evidence_type}</strong>
                    <div>
                      {ev.evidence_id}<br />
                      {ev.trust_level}
                    </div>
                  </div>
                  {i < arr.length - 1 && <div className="lineage-arrow">→</div>}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
