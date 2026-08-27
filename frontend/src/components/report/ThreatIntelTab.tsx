import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState } from '../common/Atoms';

interface ThreatIntelTabProps { result: ApkAnalysisResult; }

export function ThreatIntelTab({ result }: ThreatIntelTabProps) {
  const ea = result.engine_analysis;
  const rep = ea.reputation;

  return (
    <div>
      <h2 className="section-title">Threat intelligence</h2>
      <div className="notice">Public reputation providers are queried by SHA-256 only. FraudShield does not upload APK binaries to public services.</div>

      {ea.engines.length === 0 ? (
        <EmptyState title="No engine data" message="No threat intelligence engines produced output." />
      ) : (
        ea.engines.map(engine => (
          <section key={engine.id}>
            <h3 className="subsection-title">{engine.label}</h3>
            <div className="card padded">
              <table className="kv-table">
                <tbody>
                  <tr><td>Status</td><td><StatusPillAuto value={engine.status} /></td></tr>
                  {engine.error && <tr><td>Note</td><td style={{ color: 'var(--amber)' }}>{engine.error}</td></tr>}
                  {engine.summary && typeof engine.summary === 'object' && Object.entries(engine.summary).map(([k, v]) => (
                    <tr key={k}>
                      <td>{k.replace(/_/g, ' ')}</td>
                      <td>{typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))
      )}

      {ea.normalized_findings.length > 0 && (
        <>
          <h3 className="subsection-title">Normalized findings</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Threat intelligence findings">
              <thead>
                <tr>
                  <th>Engine</th>
                  <th>Category</th>
                  <th>Finding</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {ea.normalized_findings.map((f, i) => (
                  <tr key={i} className="no-hover">
                    <td>{f.engine}</td>
                    <td>{f.risk_category.replace(/_/g, ' ')}</td>
                    <td style={{ maxWidth: 400 }}>{f.title}</td>
                    <td><StatusPillAuto value={f.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {rep && (
        <>
          <h3 className="subsection-title">Reputation verdict</h3>
          <div className="card padded">
            <table className="kv-table">
              <tbody>
                <tr><td>Verdict</td><td><StatusPillAuto value={rep.verdict} /></td></tr>
                <tr><td>Known malicious</td><td>{rep.known_malicious ? 'Yes' : 'No'}</td></tr>
                <tr><td>Providers consulted</td><td>{rep.providers ? rep.providers.length : 0}</td></tr>
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
