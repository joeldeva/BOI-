import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState, EvidenceChip } from '../common/Atoms';

interface CodeAnalysisTabProps { result: ApkAnalysisResult; }

export function CodeAnalysisTab({ result }: CodeAnalysisTabProps) {
  const ext = result.extraction;
  const dna = result.frauddna;
  const payloads = result.recovered_payloads ?? [];
  const codeFindings = result.engine_analysis.normalized_findings.filter(f => f.risk_category === 'CODE' || f.risk_category === 'STATIC');

  return (
    <div>
      <h2 className="section-title">Code analysis</h2>

      {ext.coverage && (
        <div className="metric-strip" style={{ gridTemplateColumns: 'repeat(4,1fr)', marginBottom: 22 }}>
          {ext.coverage.dex_files !== undefined && (
            <div className="metric-box"><div className="metric-value">{String(ext.coverage.dex_files)}</div><div className="metric-label">DEX files</div></div>
          )}
          {ext.coverage.class_count !== undefined && (
            <div className="metric-box"><div className="metric-value">{String(ext.coverage.class_count)}</div><div className="metric-label">classes</div></div>
          )}
          {ext.coverage.method_count !== undefined && (
            <div className="metric-box"><div className="metric-value">{String(ext.coverage.method_count)}</div><div className="metric-label">methods</div></div>
          )}
          {payloads.length > 0 && (
            <div className="metric-box"><div className="metric-value">{payloads.length}</div><div className="metric-label">recovered payloads</div></div>
          )}
        </div>
      )}

      {dna && dna.banking_capabilities.length > 0 && (
        <>
          <h3 className="subsection-title">Banking fraud capabilities</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Banking fraud capabilities">
              <thead><tr><th>Capability</th><th>Status</th></tr></thead>
              <tbody>
                {dna.banking_capabilities.map(cap => (
                  <tr key={cap} className="no-hover">
                    <td>{cap}</td>
                    <td><StatusPillAuto value="STATIC MATCH" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {codeFindings.length > 0 && (
        <>
          <h3 className="subsection-title">Suspicious method context</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Code findings">
              <thead><tr><th>Engine</th><th>Finding</th><th>Severity</th></tr></thead>
              <tbody>
                {codeFindings.map((f, i) => (
                  <tr key={i} className="no-hover">
                    <td>{f.engine}</td>
                    <td>{f.title}</td>
                    <td><StatusPillAuto value={f.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {payloads.length > 0 && (
        <>
          <h3 className="subsection-title">Recovered payloads</h3>
          {payloads.map(p => (
            <div key={p.payload_id} className="card padded" style={{ marginBottom: 14 }}>
              <table className="kv-table">
                <tbody>
                  <tr><td>Artifact</td><td className="hash">{p.payload_id}</td></tr>
                  <tr><td>SHA-256</td><td className="hash">{p.sha256}</td></tr>
                  <tr><td>Type</td><td>{p.payload_type}</td></tr>
                  <tr><td>Source</td><td>{p.source}</td></tr>
                  <tr><td>Loader</td><td className="hash">{p.loader}</td></tr>
                  <tr><td>Analysis status</td><td><StatusPillAuto value={p.analysis_status} /></td></tr>
                  <tr>
                    <td>Capabilities</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {p.extracted_capabilities.map(c => <EvidenceChip key={c} id={c} />)}
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          ))}
        </>
      )}

      {!dna && !ext.coverage && payloads.length === 0 && codeFindings.length === 0 && (
        <EmptyState title="No code analysis data" message="Static analysis did not produce code-level data for this sample." />
      )}
    </div>
  );
}
