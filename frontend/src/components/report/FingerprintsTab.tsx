import type { ApkAnalysisResult } from '../../types/api';
import { HashValue } from '../common/HashValue';
import { EmptyState } from '../common/Atoms';

interface FingerprintsTabProps { result: ApkAnalysisResult; sha256: string; sizeBytes: number; }

export function FingerprintsTab({ result, sha256, sizeBytes }: FingerprintsTabProps) {
  const dna = result.frauddna;
  const apkidEngine = result.engine_analysis.engines.find(e => e.id === 'apkid' || e.label.toLowerCase().includes('apkid'));

  function fmtSize(b: number) {
    if (!b) return '—';
    const mb = b / 1024 / 1024;
    return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(b / 1024).toFixed(1)} KB`;
  }

  return (
    <div>
      <h2 className="section-title">Fingerprints</h2>

      <h3 className="subsection-title">File checksums</h3>
      <div className="card padded">
        <table className="kv-table">
          <tbody>
            <tr><td>SHA-256</td><td><HashValue value={sha256} /></td></tr>
            <tr><td>Size</td><td>{fmtSize(sizeBytes)}</td></tr>
          </tbody>
        </table>
      </div>

      {dna && (
        <>
          {dna.dex_fuzzy_hash && (
            <>
              <h3 className="subsection-title">DEX fuzzy hash (dexofuzzy)</h3>
              <div className="card padded">
                <HashValue value={dna.dex_fuzzy_hash} />
              </div>
            </>
          )}

          {dna.dex_fingerprints.length > 0 && (
            <>
              <h3 className="subsection-title">DEX fingerprints</h3>
              <div className="card padded">
                <table className="kv-table">
                  <tbody>
                    {dna.dex_fingerprints.map((fp, i) => (
                      <tr key={i}>
                        <td>DEX {i + 1}</td>
                        <td><HashValue value={fp} truncate /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {dna.signer_fingerprints.length > 0 && (
            <>
              <h3 className="subsection-title">Signer fingerprints</h3>
              <div className="card padded">
                <table className="kv-table">
                  <tbody>
                    {dna.signer_fingerprints.map((fp, i) => (
                      <tr key={i}>
                        <td>Signer {i + 1}</td>
                        <td><HashValue value={fp} truncate /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}

      {apkidEngine && (
        <>
          <h3 className="subsection-title">APKiD</h3>
          <div className="card padded">
            <div className="tool-block">
              <div className="analysis-band">{apkidEngine.label} — {apkidEngine.status}</div>
              {apkidEngine.error && <p style={{ color: 'var(--amber)', fontSize: 12 }}>{apkidEngine.error}</p>}
              {typeof apkidEngine.summary === 'object' && Object.entries(apkidEngine.summary).map(([k, v]) => (
                <div key={k} className="tool-row">
                  <strong>{k.replace(/_/g, ' ')}</strong>
                  <code>{String(v)}</code>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {!dna && !apkidEngine && (
        <EmptyState title="No fingerprint data available" message="Fingerprint engines did not produce output for this sample." />
      )}
    </div>
  );
}
