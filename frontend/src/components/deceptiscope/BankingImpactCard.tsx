import { DollarSign } from 'lucide-react';
import type { ApkAnalysisResult } from '../../types/api';

interface BankingImpactCardProps {
  result: ApkAnalysisResult;
}

type ImpactStatus = 'CONFIRMED' | 'SUPPORTED' | 'POSSIBLE' | 'NOT_ASSESSED';

interface ImpactItem {
  id: string;
  title: string;
  description: string;
  status: ImpactStatus;
  evidence: string[];
}

const impactStatusBadge: Record<ImpactStatus, { badge: string; text: string }> = {
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
    text: 'SUSPICIOUS INDICATOR',
  },
  NOT_ASSESSED: {
    badge: 'bg-slate-800 text-slate-400 border-slate-700',
    text: 'NOT OBSERVED',
  },
};

export function BankingImpactCard({ result }: BankingImpactCardProps) {
  const verifications = result.ai_investigation?.hypothesis_verifications ?? [];
  const extraction = result.extraction;
  const permissions = extraction.permissions?.requested ?? [];
  const codeSignals = extraction.code_signals ?? {};

  // Derive evidence-grounded statuses
  const otpInterception = verifications.find((v) => v.category === 'OTP_INTERCEPTION');
  const dataExfil = verifications.find((v) => v.category === 'DATA_EXFILTRATION');
  const accessibility = verifications.find((v) => v.category === 'ACCESSIBILITY_ABUSE');
  const dynamicLoad = verifications.find((v) => v.category === 'DYNAMIC_CODE_LOADING');

  const otpStatus: ImpactStatus =
    otpInterception?.verified_status === 'CONFIRMED'
      ? 'CONFIRMED'
      : otpInterception?.verified_status === 'SUPPORTED' || permissions.includes('android.permission.RECEIVE_SMS')
      ? 'SUPPORTED'
      : 'NOT_ASSESSED';

  const credentialStatus: ImpactStatus =
    dataExfil?.verified_status === 'CONFIRMED'
      ? 'CONFIRMED'
      : (codeSignals.credential_theft?.detected || codeSignals.phishing_indicators?.detected)
      ? 'SUPPORTED'
      : 'NOT_ASSESSED';

  const atoStatus: ImpactStatus =
    otpStatus === 'CONFIRMED' && credentialStatus === 'CONFIRMED'
      ? 'CONFIRMED'
      : otpStatus !== 'NOT_ASSESSED' || credentialStatus !== 'NOT_ASSESSED'
      ? 'SUPPORTED'
      : 'POSSIBLE';

  const transactionStatus: ImpactStatus =
    accessibility?.verified_status === 'CONFIRMED'
      ? 'CONFIRMED'
      : accessibility?.verified_status === 'SUPPORTED' || extraction.components?.accessibility_service
      ? 'SUPPORTED'
      : 'NOT_ASSESSED';

  const remoteControlStatus: ImpactStatus =
    dynamicLoad?.verified_status === 'CONFIRMED' || (result.recovered_payloads && result.recovered_payloads.length > 0)
      ? 'CONFIRMED'
      : dynamicLoad?.verified_status === 'SUPPORTED'
      ? 'SUPPORTED'
      : 'NOT_ASSESSED';

  const impacts: ImpactItem[] = [
    {
      id: 'otp_theft',
      title: 'SMS OTP Interception & Bypass',
      description: 'Intercepts multi-factor banking OTP authentication codes to bypass step-up transaction challenges.',
      status: otpStatus,
      evidence: otpInterception ? otpInterception.observed_signals : [],
    },
    {
      id: 'credential_theft',
      title: 'Banking Credential Harvesting',
      description: 'Captures internet banking usernames, passwords, and MPINs through fake overlay screens or keylogging.',
      status: credentialStatus,
      evidence: dataExfil ? dataExfil.observed_signals : [],
    },
    {
      id: 'account_takeover',
      title: 'Complete Account Takeover (ATO)',
      description: 'Combines harvested credentials with intercepted OTPs to seize control of victim banking sessions.',
      status: atoStatus,
      evidence: ['Correlation of credential harvesting and SMS interception capabilities'],
    },
    {
      id: 'unauthorized_tx',
      title: 'Automated Fraudulent Fund Transfer (ATS)',
      description: 'Abuses Android Accessibility APIs to silently automate unauthorized fund transfers without user consent.',
      status: transactionStatus,
      evidence: accessibility ? accessibility.observed_signals : [],
    },
    {
      id: 'remote_control',
      title: 'Dynamic Remote Payload Execution',
      description: 'Loads hidden second-stage banking malware payloads dynamically from memory or remote C2.',
      status: remoteControlStatus,
      evidence: dynamicLoad ? dynamicLoad.observed_signals : [],
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
          const badgeConfig = impactStatusBadge[impact.status];
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
                    {impact.status}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{impact.description}</p>
              </div>

              {impact.evidence && impact.evidence.length > 0 && (
                <div className="pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-400">
                  Signals: <span className="text-slate-300">{impact.evidence.slice(0, 3).join(', ')}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
