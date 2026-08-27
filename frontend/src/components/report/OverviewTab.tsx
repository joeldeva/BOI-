import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';

interface OverviewTabProps { result: ApkAnalysisResult; }

function findingIcon(s: string) {
  const confirmed = s === 'CONFIRMED';
  return (
    <div className={`finding-icon${confirmed ? '' : ' warn'}`}>
      {confirmed ? '✓' : '!'}
    </div>
  );
}

export function OverviewTab({ result }: OverviewTabProps) {
  const risk = result.risk;
  const imp = result.brand_impersonation;
  const bi = result.banking_impact;

  return (
    <div>
      <h2 className="section-title">Overview</h2>

      <div className="summary-grid">
        <section className="summary-box">
          <div className="summary-head">Fraud verdict</div>
          <div className="summary-body">
            {bi && bi.items.length > 0 ? (
              <div className="finding-list">
                {bi.items.map(item => (
                  <div key={item.id} className="finding-row">
                    {findingIcon(item.status)}
                    <div>
                      <div className="finding-title">{item.title}</div>
                      <div className="finding-copy">{item.description}</div>
                    </div>
                    <StatusPillAuto value={item.status} />
                  </div>
                ))}
              </div>
            ) : (
              <div className="finding-list">
                <div className="finding-row">
                  <div className="finding-icon warn">!</div>
                  <div>
                    <div className="finding-title">{result.malware_assessment.verdict.replace(/_/g, ' ')}</div>
                    <div className="finding-copy">{result.malware_assessment.explanation}</div>
                  </div>
                  <StatusPillAuto value={result.malware_assessment.verdict} />
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="summary-box">
          <div className="summary-head">Deterministic risk composition</div>
          <div className="summary-body">
            <div className="score-breakdown">
              {risk.static_score !== undefined && (
                <div className="score-item">
                  <span>Static analysis</span>
                  <div className="score-bar"><span style={{ width: `${risk.static_score ?? 0}%` }} /></div>
                  <span className="score-value">{risk.static_score ?? '—'}</span>
                </div>
              )}
              {risk.runtime_adjustment !== undefined && risk.runtime_adjustment !== null && (
                <div className="score-item">
                  <span>Runtime verified</span>
                  <div className="score-bar"><span style={{ width: `${risk.runtime_adjustment}%` }} /></div>
                  <span className="score-value">+{risk.runtime_adjustment}</span>
                </div>
              )}
              <div className="score-item">
                <span>Fraud delta</span>
                <div className="score-bar"><span style={{ width: `${result.fraud_delta.score}%` }} /></div>
                <span className="score-value">{result.fraud_delta.score}</span>
              </div>
            </div>
            <table className="kv-table" style={{ marginTop: 12 }}>
              <tbody>
                <tr><td>Final risk</td><td><strong>{risk.overall_score} / 100</strong>{' '}<StatusPillAuto value={risk.severity} /></td></tr>
                <tr><td>Confidence</td><td>{((risk.confidence ?? 0) * 100).toFixed(0)}%</td></tr>
                <tr><td>Analysis quality</td><td>{result.extraction.analysis_quality ?? '—'}</td></tr>
                <tr><td>Dynamic status</td><td><StatusPillAuto value={result.experiment_results.length > 0 ? 'COMPLETED' : 'UNAVAILABLE'} /></td></tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <h2 className="subsection-title">Application identity</h2>
      <div className="card padded">
        <table className="kv-table">
          <tbody>
            <tr><td>App name</td><td>{result.extraction.app.app_label ?? '—'}</td></tr>
            <tr><td>Package</td><td>{result.extraction.app.package_name ?? '—'}</td></tr>
            <tr><td>Version</td><td>{result.extraction.app.version_name ?? '—'}{result.extraction.app.version_code ? ` (${result.extraction.app.version_code})` : ''}</td></tr>
            <tr><td>Min / target SDK</td><td>{result.extraction.app.min_sdk ?? '—'} / {result.extraction.app.target_sdk ?? '—'}</td></tr>
          </tbody>
        </table>
      </div>

      {bi && bi.items.length > 0 && (
        <>
          <h2 className="subsection-title">Banking impact</h2>
          <div className="table-wrap">
            <table className="data-table" aria-label="Banking fraud impact">
              <thead><tr><th>Capability</th><th>Status</th><th>Basis</th></tr></thead>
              <tbody>
                {bi.items.map(item => (
                  <tr key={item.id} className="no-hover">
                    <td>{item.title}</td>
                    <td><StatusPillAuto value={item.status} /></td>
                    <td style={{ fontSize: 12, color: '#555' }}>{item.deterministic_basis}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h2 className="subsection-title">Bank impersonation analysis</h2>
      <div className="card padded">
        {imp ? (
          <table className="kv-table">
            <tbody>
              <tr><td>Target brand</td><td>{imp.target_bank_name ?? '—'}</td></tr>
              <tr><td>App-name similarity</td><td>{imp.app_label_similarity !== undefined ? `${(imp.app_label_similarity * 100).toFixed(0)}%` : '—'}</td></tr>
              <tr><td>Package mismatch</td><td><StatusPillAuto value={imp.is_official_package ? 'OFFICIAL' : 'SUSPICIOUS'} /></td></tr>
              <tr><td>Official signer inventory</td><td><StatusPillAuto value={imp.signer_reference_status === 'NOT_CONFIGURED' ? 'NOT CONFIGURED' : imp.is_trusted_signer ? 'TRUSTED' : 'UNTRUSTED'} /></td></tr>
              <tr><td>Icon reference</td><td><StatusPillAuto value={imp.icon_reference_status === 'NOT_CONFIGURED' ? 'NOT CONFIGURED' : imp.icon_similarity !== null ? 'CONFIGURED' : 'NOT CONFIGURED'} /></td></tr>
              <tr><td>Verdict</td><td><StatusPillAuto value={imp.verdict} /></td></tr>
            </tbody>
          </table>
        ) : (
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>
            Bank impersonation analysis was not performed or profile not loaded.{' '}
            <StatusPillAuto value="NOT CONFIGURED" />
          </p>
        )}
      </div>
    </div>
  );
}
