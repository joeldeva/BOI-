import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState } from '../common/Atoms';

interface NetworkAnalysisTabProps { result: ApkAnalysisResult; }

export function NetworkAnalysisTab({ result }: NetworkAnalysisTabProps) {
  const ni = result.extraction.network_indicators;
  const firebase = result.firebase_infrastructure;
  const runtime = result.runtime_evidence ?? [];
  const networkEvidence = runtime.filter(e => e.evidence_type === 'network' || e.evidence_type?.toLowerCase().includes('http') || e.evidence_type?.toLowerCase().includes('request'));
  const hasPayloadCorrelated = runtime.some(e => e.trust_level === 'PAYLOAD_CORRELATED');
  const hasAnyNetworkData = ni.domains.length || ni.ips.length || ni.urls.length || networkEvidence.length;

  if (!hasAnyNetworkData && !firebase) {
    return (
      <div>
        <h2 className="section-title">Network analysis</h2>
        <EmptyState title="No network indicators" message="No network infrastructure was extracted from this sample." />
      </div>
    );
  }

  return (
    <div>
      <h2 className="section-title">Network analysis</h2>

      {ni.domains.length > 0 && (
        <>
          <h3 className="subsection-title">Observed domains</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Network domains">
              <thead><tr><th>Domain</th></tr></thead>
              <tbody>
                {ni.domains.map((d, i) => (
                  <tr key={i} className="no-hover">
                    <td className="hash">{d}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {ni.ips.length > 0 && (
        <>
          <h3 className="subsection-title">IP addresses</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="IP addresses">
              <thead><tr><th>IP</th></tr></thead>
              <tbody>
                {ni.ips.map((ip, i) => (
                  <tr key={i} className="no-hover">
                    <td className="hash">{ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {ni.urls.length > 0 && (
        <>
          <h3 className="subsection-title">URLs</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="URLs">
              <thead><tr><th>URL</th></tr></thead>
              <tbody>
                {ni.urls.map((u, i) => (
                  <tr key={i} className="no-hover">
                    <td className="hash">{u}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {networkEvidence.length > 0 && (
        <>
          <h3 className="subsection-title">HTTP observations</h3>
          <div className="card padded">
            {networkEvidence.map((ev, i) => (
              <div key={i} style={{ padding: '8px 0', borderBottom: i < networkEvidence.length - 1 ? '1px solid var(--line)' : undefined }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{ev.evidence_type}</span>
                  {ev.trust_level && <StatusPillAuto value={ev.trust_level} />}
                </div>
                <div style={{ fontSize: 12, color: '#777', marginTop: 3 }}>{ev.description}</div>
              </div>
            ))}
          </div>
          {hasPayloadCorrelated && (
            <div className="warning-notice" style={{ marginTop: 10 }}>
              Sensitive values are masked in analyst views. The verifier stores evidence IDs and correlation status rather than exposing full banking secrets.
            </div>
          )}
        </>
      )}

      {firebase && (
        <>
          <h3 className="subsection-title">Firebase infrastructure</h3>
          <div className="card padded">
            <table className="kv-table">
              <tbody>
                {firebase.project_id && <tr><td>Project ID</td><td className="hash">{firebase.project_id}</td></tr>}
                {firebase.api_key && <tr><td>API key</td><td className="hash">{firebase.api_key.slice(0, 12)}…</td></tr>}
                {firebase.database_urls && firebase.database_urls.length > 0 && <tr><td>Database URLs</td><td className="hash">{firebase.database_urls.join(', ')}</td></tr>}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
