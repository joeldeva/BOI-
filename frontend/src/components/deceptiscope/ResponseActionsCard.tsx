import { Zap } from 'lucide-react';
import type { ApkAnalysisResult } from '../../types/api';

interface ResponseActionsCardProps {
  result: ApkAnalysisResult;
}

export function ResponseActionsCard({ result }: ResponseActionsCardProps) {
  const risk = result.risk;
  const isHighRisk = risk.overall_score >= 60;
  const hasFirebase = Boolean(result.firebase_infrastructure?.project_id);
  const brandTarget = result.brand_impersonation?.target_bank_name;
  const hasRecoveredPayloads = Boolean(result.recovered_payloads && result.recovered_payloads.length > 0);

  const actions: { id: string; priority: 'CRITICAL' | 'HIGH' | 'MEDIUM'; title: string; detail: string }[] = [];

  if (isHighRisk) {
    actions.push({
      id: 'block_hash',
      priority: 'CRITICAL',
      title: 'Block Sample Hashes & Ingest into EDR / Antivirus Feeds',
      detail: `Block APK SHA-256 (${result.analysis_id.slice(0, 16)}...) and distribute threat indicators to gateway firewalls.`,
    });
  }

  if (brandTarget && result.brand_impersonation?.verdict !== 'OFFICIAL_LEGITIMATE') {
    actions.push({
      id: 'brand_takedown',
      priority: 'CRITICAL',
      title: `Initiate Brand Takedown for ${brandTarget}`,
      detail: `Submit domain/host abuse takedown notices for infringing endpoints and distribution portals.`,
    });
  }

  if (hasFirebase) {
    actions.push({
      id: 'firebase_abuse',
      priority: 'HIGH',
      title: 'Report Malicious Firebase Backend Project',
      detail: `Report Firebase project '${result.firebase_infrastructure?.project_id}' to Google Cloud Trust & Safety for credential harvesting abuse.`,
    });
  }

  if (hasRecoveredPayloads) {
    actions.push({
      id: 'payload_iocs',
      priority: 'HIGH',
      title: 'Block Second-Stage Dropped Payloads',
      detail: `${result.recovered_payloads?.length} dynamic payload(s) recovered. Ingest secondary DEX hashes into IOC blocklists.`,
    });
  }

  actions.push({
    id: 'step_up_auth',
    priority: isHighRisk ? 'HIGH' : 'MEDIUM',
    title: 'Enforce Step-Up Out-of-Band Verification on Suspicious Sessions',
    detail: 'Require hardware token or biometric re-authentication for transactions originating from devices with unverified APKs.',
  });

  return (
    <section className="soc-card p-6 space-y-4" data-testid="response-actions-section">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Zap className="w-5 h-5 text-yellow-400" />
          <h3 className="text-base font-bold text-white">Recommended Response &amp; Mitigation Actions</h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">SOC / Fraud Operations Playbook</span>
      </div>

      <div className="space-y-2.5">
        {actions.map((act) => (
          <div
            key={act.id}
            className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span
                  className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border uppercase ${
                    act.priority === 'CRITICAL'
                      ? 'bg-red-500/20 text-red-300 border-red-500/30'
                      : act.priority === 'HIGH'
                      ? 'bg-orange-500/20 text-orange-300 border-orange-500/30'
                      : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                  }`}
                >
                  {act.priority}
                </span>
                <p className="text-xs font-bold text-white">{act.title}</p>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{act.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
