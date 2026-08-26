import { Dna } from 'lucide-react';
import type { Campaign, FraudDNAFingerprint, RelatedSample } from '../../types/api';

interface FraudDNACampaignCardProps {
  frauddna?: FraudDNAFingerprint;
  campaign?: Campaign;
  relatedSamples?: RelatedSample[];
}

export function FraudDNACampaignCard({ frauddna, campaign, relatedSamples }: FraudDNACampaignCardProps) {
  if (!frauddna && !campaign && (!relatedSamples || relatedSamples.length === 0)) {
    return null;
  }

  return (
    <section className="soc-card p-6 space-y-5" data-testid="frauddna-section">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Dna className="w-5 h-5 text-cyan-400" />
          <h3 className="text-base font-bold text-white">FraudDNA &amp; Threat Campaign Correlation</h3>
        </div>
        {campaign && (
          <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
            Campaign: {campaign.campaign_id}
          </span>
        )}
      </div>

      {campaign && (
        <div className="p-4 rounded-lg bg-cyan-950/20 border border-cyan-500/30 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <p className="text-xs font-mono uppercase text-cyan-400 font-bold">Threat Cluster Identity</p>
              <h4 className="text-sm font-bold text-white">{campaign.name}</h4>
            </div>
            <span className="text-xs font-mono text-cyan-300">
              {campaign.member_sha256s.length} correlated sample{campaign.member_sha256s.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
            {campaign.shared_firebase_projects.length > 0 && (
              <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Shared Firebase Projects</span>
                <p className="font-mono text-cyan-300 truncate">{campaign.shared_firebase_projects.join(', ')}</p>
              </div>
            )}
            {campaign.shared_infrastructure.length > 0 && (
              <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Shared C2 Infrastructure</span>
                <p className="font-mono text-slate-300 truncate">{campaign.shared_infrastructure.slice(0, 3).join(', ')}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {relatedSamples && relatedSamples.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-bold text-slate-300 uppercase tracking-wider">
            Correlated Banking Malware Samples ({relatedSamples.length})
          </p>
          <div className="space-y-2.5">
            {relatedSamples.map((sample) => (
              <div
                key={sample.sha256}
                className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-white truncate">
                      {sample.app_label || sample.package_name || 'Correlated Sample'}
                    </span>
                    {sample.campaign_id && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                        {sample.campaign_id}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] font-mono text-slate-400 break-all">
                    SHA-256: <span className="text-slate-300">{sample.sha256}</span>
                  </p>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {sample.reasons.map((reason, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-500/15 text-blue-300 border border-blue-500/20"
                      >
                        ✓ {reason}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                  <div className="text-right">
                    <p className="text-[10px] uppercase font-bold text-slate-500">Similarity</p>
                    <p className="text-sm font-mono font-bold text-cyan-300">
                      {(sample.similarity * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
