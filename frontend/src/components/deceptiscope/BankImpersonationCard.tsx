import { Building, Flame } from 'lucide-react';
import type { BrandImpersonationResult, FirebaseInfrastructure } from '../../types/api';

interface BankImpersonationCardProps {
  brandImpersonation?: BrandImpersonationResult;
  firebaseInfrastructure?: FirebaseInfrastructure;
}

const verdictBadgeStyle: Record<string, string> = {
  VERY_HIGH: 'bg-red-500/20 text-red-300 border-red-500/40',
  HIGH: 'bg-red-500/15 text-red-300 border-red-500/30',
  SUSPICIOUS: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  NONE: 'bg-slate-800 text-slate-300 border-slate-700',
  OFFICIAL_LEGITIMATE: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
};

export function BankImpersonationCard({
  brandImpersonation,
  firebaseInfrastructure,
}: BankImpersonationCardProps) {
  if (!brandImpersonation && !firebaseInfrastructure) {
    return null;
  }

  const isImpersonating =
    brandImpersonation &&
    ['VERY_HIGH', 'HIGH', 'SUSPICIOUS'].includes(brandImpersonation.verdict);
  const isLegitimate = brandImpersonation?.verdict === 'OFFICIAL_LEGITIMATE';

  return (
    <section className="soc-card p-6 space-y-5" data-testid="bank-impersonation-section">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Building className="w-5 h-5 text-indigo-400" />
          <h3 className="text-base font-bold text-white">Banking-Brand Impersonation &amp; Infrastructure</h3>
        </div>
        {brandImpersonation && (
          <span
            className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold border uppercase ${
              verdictBadgeStyle[brandImpersonation.verdict] ?? verdictBadgeStyle.NONE
            }`}
          >
            {brandImpersonation.verdict.replaceAll('_', ' ')}
          </span>
        )}
      </div>

      {brandImpersonation && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <p className="text-[10px] uppercase font-bold text-slate-400">Target Financial Institution</p>
                <h4 className="text-base font-bold text-white">
                  {brandImpersonation.target_bank_name || 'No Specific Target Detected'}
                </h4>
              </div>
              <div className="text-right">
                <p className="text-[10px] uppercase font-bold text-slate-400">Impersonation Score</p>
                <p
                  className={`text-base font-mono font-bold ${
                    isImpersonating ? 'text-red-400' : isLegitimate ? 'text-emerald-400' : 'text-slate-300'
                  }`}
                >
                  {(brandImpersonation.impersonation_score * 100).toFixed(0)}/100
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs pt-1">
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Title Similarity</span>
                <p className="font-mono font-bold text-slate-200">
                  {(brandImpersonation.app_label_similarity * 100).toFixed(0)}%
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Icon Visual Sim</span>
                <p className="font-mono font-bold text-slate-200">
                  {brandImpersonation.icon_similarity != null
                    ? `${(brandImpersonation.icon_similarity * 100).toFixed(0)}%`
                    : 'N/A'}
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Official Package</span>
                <p
                  className={`font-mono font-bold ${
                    brandImpersonation.is_official_package ? 'text-emerald-400' : 'text-slate-400'
                  }`}
                >
                  {brandImpersonation.is_official_package ? 'MATCH' : 'NO MATCH'}
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Trusted Signer</span>
                <p
                  className={`font-mono font-bold ${
                    brandImpersonation.is_trusted_signer ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  {brandImpersonation.is_trusted_signer ? 'VERIFIED' : 'UNTRUSTED'}
                </p>
              </div>
            </div>

            {brandImpersonation.reasons.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
                <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  Brand Analysis Evidence Signals
                </p>
                <div className="space-y-1">
                  {brandImpersonation.reasons.map((reason, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-xs text-slate-300">
                      <span className="text-amber-400 shrink-0">▸</span>
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {firebaseInfrastructure && firebaseInfrastructure.project_id && (
        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-400" />
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Firebase Backend Infrastructure
            </h4>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Project ID</span>
              <p className="font-mono text-cyan-300 font-bold">{firebaseInfrastructure.project_id}</p>
            </div>
            {firebaseInfrastructure.storage_bucket && (
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Storage Bucket</span>
                <p className="font-mono text-slate-300 truncate">{firebaseInfrastructure.storage_bucket}</p>
              </div>
            )}
            {firebaseInfrastructure.firebase_url && (
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400">Database Endpoint</span>
                <p className="font-mono text-slate-300 truncate">{firebaseInfrastructure.firebase_url}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
