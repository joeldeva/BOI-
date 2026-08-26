import { DollarSign } from 'lucide-react';
import type { ApkAnalysisResult, BankingImpactItem, BankingImpactStatus } from '../../types/api';

interface BankingImpactCardProps {
  result: ApkAnalysisResult;
}

const impactStatusBadge: Record<BankingImpactStatus, { badge: string; text: string }> = {
  CONFIRMED: {
    badge: 'bg-red-500/20 text-red-300 border-red-500/40',
    text: 'CONFIRMED BY SANDBOX PROOF',
  },
  SUPPORTED: {
    badge: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
    text: 'STATICALLY SUPPORTED',
  },
  POSSIBLE: {
    badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    text: 'POTENTIAL PREREQUISITE RISK',
  },
  NOT_OBSERVED: {
    badge: 'bg-slate-800 text-slate-400 border-slate-700',
    text: 'NOT OBSERVED',
  },
};

export function BankingImpactCard({ result }: BankingImpactCardProps) {
  // Use backend derived impact directly; fallback to fallback derivation if viewing legacy cached record
  const backendImpact = result.banking_impact?.items;

  const impacts: BankingImpactItem[] = backendImpact && backendImpact.length > 0
    ? backendImpact
    : [
        {
          id: 'otp_interception',
          category: 'OTP_INTERCEPTION',
          title: 'SMS OTP Interception & Bypass',
          description: 'Intercepts multi-factor banking OTP authentication codes to bypass step-up transaction challenges.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No SMS read/receive capabilities or runtime interception observed.',
          evidence_ids: [],
          signals: [],
        },
        {
          id: 'credential_exfiltration',
          category: 'CREDENTIAL_EXFILTRATION',
          title: 'Banking Credential Harvesting & Exfiltration',
          description: 'Captures internet banking usernames, passwords, and MPINs through fake overlay screens or keylogging.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No credential theft signals or outbound exfiltration observed.',
          evidence_ids: [],
          signals: [],
        },
        {
          id: 'account_takeover_risk',
          category: 'ACCOUNT_TAKEOVER_RISK',
          title: 'Account Takeover (ATO) Risk',
          description: 'Combines harvested credentials with intercepted OTPs to seize unauthorized control of victim bank accounts.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No prerequisite credential harvesting or OTP interception capabilities observed.',
          evidence_ids: [],
          signals: [],
        },
        {
          id: 'accessibility_abuse',
          category: 'ACCESSIBILITY_ABUSE',
          title: 'Accessibility Service Exploitation',
          description: 'Abuses Android Accessibility APIs to observe user credentials, inject gestures, and bypass user interaction.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No accessibility service or interaction capabilities observed.',
          evidence_ids: [],
          signals: [],
        },
        {
          id: 'automated_transaction_risk',
          category: 'AUTOMATED_TRANSACTION_RISK',
          title: 'Automated Fraudulent Transaction (ATS) Risk',
          description: 'Automates unauthorized fund transfers using compromised accessibility services without explicit victim consent.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No automated UI control or accessibility service observed.',
          evidence_ids: [],
          signals: [],
        },
        {
          id: 'dynamic_code_loading',
          category: 'DYNAMIC_CODE_LOADING',
          title: 'Dynamic Remote Payload Execution',
          description: 'Loads hidden second-stage banking malware payloads dynamically from memory, DEX files, or remote servers.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No dynamic class loading APIs or runtime execution observed.',
          evidence_ids: [],
          signals: [],
        },
        {
          id: 'second_stage_payload',
          category: 'SECOND_STAGE_PAYLOAD',
          title: 'Secondary Payload Dropper',
          description: 'Drops and unpacks secondary executable payload files to conceal malicious behaviors from static scanners.',
          status: 'NOT_OBSERVED',
          deterministic_basis: 'No secondary payloads were dropped or recovered.',
          evidence_ids: [],
          signals: [],
        },
      ];

  return (
    <section className="soc-card p-6 space-y-5" data-testid="banking-impact-section">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <DollarSign className="w-5 h-5 text-emerald-400" />
          <h3 className="text-base font-bold text-white">Banking Fraud &amp; Financial Impact Matrix</h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Deterministic Evidence-Grounded Impact Translation
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {impacts.map((impact) => {
          const badgeConfig = impactStatusBadge[impact.status] || impactStatusBadge.NOT_OBSERVED;
          return (
            <div
              key={impact.id}
              className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5 flex flex-col justify-between"
            >
              <div className="space-y-1.5">
                <div className="flex items-start justify-between gap-2">
                  <h4 className="text-xs font-bold text-white">{impact.title}</h4>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border uppercase shrink-0 ${badgeConfig.badge}`}
                  >
                    {impact.status.replace('_', ' ')}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{impact.description}</p>
                <p className="text-[11px] text-slate-300 italic">{impact.deterministic_basis}</p>
              </div>

              {(impact.evidence_ids?.length > 0 || impact.signals?.length > 0) && (
                <div className="pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-400 space-y-1">
                  {impact.evidence_ids?.length > 0 && (
                    <div>
                      Evidence IDs: <span className="text-emerald-400">{impact.evidence_ids.join(', ')}</span>
                    </div>
                  )}
                  {impact.signals?.length > 0 && (
                    <div>
                      Signals: <span className="text-slate-300">{impact.signals.slice(0, 4).join(', ')}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
