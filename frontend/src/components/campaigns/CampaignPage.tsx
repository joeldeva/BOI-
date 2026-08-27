import type { ApkAnalysisRecord } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState } from '../common/Atoms';

interface CampaignPageProps {
  recentApks: ApkAnalysisRecord[];
  onOpenReport: (id: string) => void;
}

export function CampaignPage({ recentApks, onOpenReport }: CampaignPageProps) {
  const campaignSamples = recentApks.filter(a => a.result?.campaign);

  return (
    <main className="main">
      <h2 className="section-title">FraudDNA Campaigns</h2>
      <p className="section-note">
        Persistent clusters built from uploaded APK fingerprints and hard cross-sample anchors.
      </p>

      {campaignSamples.length === 0 ? (
        <EmptyState
          title="No campaign clusters identified yet."
          message="Campaign clusters automatically assemble when multiple uploaded samples share signers, C2 infrastructure, or DEX payloads."
        />
      ) : (
        <div className="table-wrap">
          <table className="data-table" aria-label="FraudDNA campaigns">
            <thead>
              <tr>
                <th>App Name</th>
                <th>Package</th>
                <th>Campaign</th>
                <th>Anchors</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {campaignSamples.map(a => {
                const c = a.result!.campaign!;
                return (
                  <tr key={a.id} onClick={() => onOpenReport(a.id)} tabIndex={0} role="button">
                    <td><strong>{a.app_name ?? a.file_name}</strong></td>
                    <td>{a.package_name ?? '—'}</td>
                    <td>
                      <strong>{c.name}</strong>
                      <div className="hash">{c.campaign_id}</div>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {[
                        c.shared_signer_fingerprints.length ? 'Signer reuse' : null,
                        c.shared_infrastructure.length ? 'C2 overlap' : null,
                        c.shared_firebase_projects.length ? 'Firebase' : null,
                      ].filter(Boolean).join(' · ')}
                    </td>
                    <td><StatusPillAuto value={a.severity ?? 'HIGH'} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
