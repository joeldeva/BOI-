import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { HashValue } from '../common/HashValue';
import { EmptyState } from '../common/Atoms';

interface FraudDnaTabProps { result: ApkAnalysisResult; }

export function FraudDnaTab({ result }: FraudDnaTabProps) {
  const dna = result.frauddna;
  const related = result.related_samples ?? [];
  const campaign = result.campaign;

  if (!dna && !campaign && related.length === 0) {
    return (
      <div>
        <h2 className="section-title">FraudDNA</h2>
        <EmptyState title="No FraudDNA data" message="FraudDNA fingerprinting did not produce cross-sample correlation data for this sample." />
      </div>
    );
  }

  return (
    <div>
      <h2 className="section-title">FraudDNA</h2>
      <div className="notice">
        Cross-sample correlation uses persistent fingerprints and hard anchors. Campaign state is stored in the database and survives worker/API restarts.
      </div>

      {dna && (
        <>
          <h3 className="subsection-title">Fingerprints</h3>
          <div className="card padded">
            <table className="kv-table">
              <tbody>
                {dna.dex_fuzzy_hash && <tr><td>DEX fuzzy hash</td><td><HashValue value={dna.dex_fuzzy_hash} truncate /></td></tr>}
                {dna.signer_fingerprints.length > 0 && (
                  <tr>
                    <td>Signer fingerprints</td>
                    <td>{dna.signer_fingerprints.map((fp, i) => <div key={i}><HashValue value={fp} truncate /></div>)}</td>
                  </tr>
                )}
                {dna.banking_capabilities.length > 0 && (
                  <tr>
                    <td>Banking capabilities</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {dna.banking_capabilities.map(c => (
                          <span key={c} className="chip">{c}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {related.length > 0 && (
        <>
          <h3 className="subsection-title">Related samples</h3>
          <div className="table-wrap">
            <table className="data-table" aria-label="Related samples">
              <thead>
                <tr>
                  <th>SHA256</th>
                  <th>Similarity</th>
                  <th>Reasons</th>
                  <th>Campaign</th>
                </tr>
              </thead>
              <tbody>
                {related.map((s, i) => (
                  <tr key={i} className="no-hover">
                    <td className="hash">{s.sha256.slice(0, 12)}…{s.sha256.slice(-8)}</td>
                    <td>
                      <div className="similarity-bar">
                        <span style={{ width: `${(s.similarity * 100).toFixed(0)}%` }} />
                        <em>{(s.similarity * 100).toFixed(0)}%</em>
                      </div>
                    </td>
                    <td style={{ fontSize: 12 }}>{s.reasons.join(' · ')}</td>
                    <td>{s.campaign_id ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {campaign && (
        <>
          <h3 className="subsection-title">Campaign hard anchors</h3>
          <div className="card padded">
            <table className="kv-table">
              <tbody>
                <tr><td>Campaign ID</td><td className="hash">{campaign.campaign_id}</td></tr>
                <tr><td>Name</td><td>{campaign.name}</td></tr>
                <tr><td>Members</td><td>{campaign.member_sha256s.length} samples</td></tr>
                {campaign.shared_signer_fingerprints.length > 0 && (
                  <tr><td>Signer reuse</td><td><StatusPillAuto value="CONFIRMED" /></td></tr>
                )}
                {campaign.shared_infrastructure.length > 0 && (
                  <tr><td>C2 overlap</td><td><StatusPillAuto value="CONFIRMED" /></td></tr>
                )}
                {campaign.shared_firebase_projects.length > 0 && (
                  <tr><td>Firebase identity</td><td><StatusPillAuto value="SUPPORTED" /></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
