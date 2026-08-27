import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState, EvidenceChip } from '../common/Atoms';

interface AiInvestigationTabProps { result: ApkAnalysisResult; }

export function AiInvestigationTab({ result }: AiInvestigationTabProps) {
  const ai = result.ai_investigation;
  if (!ai) return (
    <div>
      <h2 className="section-title">AI investigation</h2>
      <EmptyState title="AI investigation not available" message="No AI investigation was produced for this sample." />
    </div>
  );

  return (
    <div>
      <h2 className="section-title">AI investigation</h2>
      <div className="notice">
        AI produces bounded hypotheses from evidence IDs. Final confirmation comes from deterministic verifier logic, not model confidence.
      </div>
      {ai.warning && <div className="warning-notice">{ai.warning}</div>}

      <h3 className="subsection-title">Investigation control flow</h3>
      <div className="card padded">
        <div className="lineage">
          {[
            { label: 'Evidence', copy: 'Static + engine + reputation + runtime-capability signals' },
            { label: 'AI hypothesis', copy: 'Evidence-grounded fraud theory with cited evidence IDs' },
            { label: 'Controlled experiment', copy: 'Strict backend-owned ExperimentType' },
            { label: 'Runtime evidence', copy: 'Trusted emulator + Frida observers' },
            { label: 'Deterministic verdict', copy: 'Trust, lineage and exact behavior rules', isProof: true },
          ].map((n, i, arr) => (
            <div key={n.label} style={{ display: 'contents' }}>
              <div className={`lineage-node${n.isProof ? ' proof' : ''}`}>
                <strong>{n.label}</strong>
                <div>{n.copy}</div>
              </div>
              {i < arr.length - 1 && <div className="lineage-arrow">→</div>}
            </div>
          ))}
        </div>
      </div>

      {ai.hypotheses.length === 0 ? (
        <EmptyState title="No hypotheses generated" />
      ) : (
        <>
          <h3 className="subsection-title">Hypotheses</h3>
          {ai.hypotheses.map(h => (
            <div key={h.hypothesis_id} className="hypothesis-card">
              <div className="hypothesis-head">
                <span className="hypothesis-id">{h.hypothesis_id}</span>
                <div className="hypothesis-title">{h.title}</div>
                <StatusPillAuto value={h.status} />
              </div>
              <div className="hypothesis-body">
                <div>
                  <div className="label">Evidence reasoning</div>
                  <p>{h.reasoning_summary}</p>
                  <div className="evidence-chips">
                    {h.supporting_evidence_ids.map(id => <EvidenceChip key={id} id={id} />)}
                  </div>
                </div>
                <div>
                  <div className="label">Controlled validation</div>
                  <p>
                    <strong>{h.recommended_experiment_types.join(', ') || 'N/A'}</strong><br />
                    Confidence: {h.confidence !== undefined ? `${(h.confidence * 100).toFixed(0)}%` : 'N/A'}<br />
                    No AI-supplied ADB, shell or Frida JavaScript.
                  </p>
                </div>
              </div>
            </div>
          ))}
        </>
      )}

      {ai.hypothesis_verifications && ai.hypothesis_verifications.length > 0 && (
        <>
          <h3 className="subsection-title">Verification results</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Hypothesis verifications">
              <thead><tr><th>Hypothesis</th><th>Verified status</th><th>Explanation</th></tr></thead>
              <tbody>
                {ai.hypothesis_verifications.map((v, i) => (
                  <tr key={i} className="no-hover">
                    <td>{v.hypothesis_id}</td>
                    <td><StatusPillAuto value={v.verified_status} /></td>
                    <td style={{ fontSize: 12 }}>{v.deterministic_explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
