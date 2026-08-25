import { useState } from 'react';
import {
  AlertTriangle,
  Check,
  CircleHelp,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  FileText,
  Fingerprint,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import { ScoreGauge } from '../common/ScoreGauge';
import { SeverityBadge } from '../common/SeverityBadge';
import { SyntheticBadge } from '../common/SyntheticBadge';
import { InvestigationTimeline } from './InvestigationTimeline';
import { ProvenanceGraph } from './ProvenanceGraph';
import type { ApkAnalysisRecord } from '../../types/api';

interface ApkAnalysisViewProps {
  analysis: ApkAnalysisRecord;
  onDownloadPdf: (id: string) => void;
}

const verdictStyle: Record<string, string> = {
  KNOWN_MALICIOUS: 'border-red-500/60 bg-red-950/50 text-red-200',
  HIGH_RISK: 'border-red-500/50 bg-red-950/40 text-red-200',
  SUSPICIOUS: 'border-orange-500/50 bg-orange-950/40 text-orange-200',
  REVIEW_REQUIRED: 'border-amber-500/50 bg-amber-950/40 text-amber-200',
  INCONCLUSIVE: 'border-amber-500/50 bg-amber-950/40 text-amber-200',
  LOW_RISK_OBSERVED: 'border-emerald-500/40 bg-emerald-950/30 text-emerald-200',
};

const investigationStatusStyle: Record<string, string> = {
  completed: 'text-emerald-300 border-emerald-500/30 bg-emerald-950/20',
  disabled: 'text-slate-300 border-slate-700 bg-slate-950/40',
  failed: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
  unavailable: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
};

const experimentStatusStyle: Record<string, string> = {
  PLANNED: 'text-blue-300 border-blue-500/30 bg-blue-950/20',
  SKIPPED: 'text-slate-300 border-slate-700 bg-slate-950/40',
  UNSUPPORTED: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
  UNAVAILABLE: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
  RUNNING: 'text-violet-300 border-violet-500/30 bg-violet-950/20',
  COMPLETED: 'text-emerald-300 border-emerald-500/30 bg-emerald-950/20',
  FAILED: 'text-red-300 border-red-500/30 bg-red-950/20',
  TIMED_OUT: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
};

export function ApkAnalysisView({ analysis, onDownloadPdf }: ApkAnalysisViewProps) {
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const result = analysis.result;

  const copyToClipboard = (value: string) => {
    void navigator.clipboard.writeText(value);
    setCopiedValue(value);
    window.setTimeout(() => setCopiedValue(null), 2000);
  };

  if (!result) {
    return (
      <div className="soc-card p-6 space-y-3">
        <div className="flex items-center justify-between gap-4">
          <div><h2 className="text-xl font-display font-extrabold text-white">{analysis.file_name}</h2><p className="text-xs font-mono text-slate-400">{analysis.id}</p></div>
          <span className="uppercase text-xs font-bold text-slate-300">{analysis.status}</span>
        </div>
        <div className="p-4 rounded-lg bg-amber-950/30 border border-amber-500/40 text-sm text-amber-200">
          {analysis.error_message ?? 'Analysis evidence is not available yet. Refresh after the job reaches a terminal state.'}
          {analysis.error_code && <p className="font-mono text-xs mt-2">Error code: {analysis.error_code}</p>}
        </div>
      </div>
    );
  }

  const risk = result.risk;
  const assessment = result.malware_assessment;
  const engineAnalysis = result.engine_analysis;
  const aiInvestigation = result.ai_investigation;
  const experimentPlan = aiInvestigation?.experiment_plan ?? [];
  const isPartial = analysis.analysis_quality === 'partial';
  const networkValues = [
    ...result.extraction.network_indicators.domains,
    ...result.extraction.network_indicators.ips,
    ...result.extraction.network_indicators.urls,
  ];

  return (
    <div className="space-y-6">
      <section className="soc-card p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-xl font-display font-extrabold text-white truncate">{analysis.file_name}</h2>
              <SeverityBadge severity={analysis.severity ?? risk.severity} size="md" />
              {analysis.data_origin === 'synthetic' && <SyntheticBadge />}
            </div>
            <p className="text-xs font-mono text-slate-400 break-all">SHA-256: <span className="text-slate-200">{analysis.sha256}</span></p>
          </div>
          <button onClick={() => onDownloadPdf(analysis.id)} className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/20">
            <Download className="w-4 h-4" />Download evidence PDF
          </button>
        </div>

        <div className={`p-4 rounded-lg border ${verdictStyle[assessment.verdict] ?? verdictStyle.INCONCLUSIVE}`}>
          <div className="flex items-start gap-3">
            {assessment.verdict === 'LOW_RISK_OBSERVED' ? <CircleHelp className="w-5 h-5 shrink-0 mt-0.5" /> : <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5" />}
            <div className="space-y-1">
              <p className="font-mono text-xs font-extrabold tracking-wider">MALWARE ASSESSMENT: {assessment.verdict.replaceAll('_', ' ')}</p>
              <p className="text-sm">{assessment.explanation}</p>
              <p className="text-xs opacity-90"><strong>Legitimacy:</strong> not established · <strong>Safe to install:</strong> no such claim is made · <strong>Known malware:</strong> {String(assessment.known_malware)}</p>
            </div>
          </div>
        </div>

        {isPartial && (
          <div className="p-4 rounded-lg bg-amber-950/40 border border-amber-500/50 text-amber-200 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-xs"><strong>PARTIAL EXTRACTION:</strong> DEX, manifest or certificate coverage was incomplete. Absence of a finding must not be presented as proof of safety.</div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          <div className="flex items-center justify-center p-4 rounded-lg bg-slate-950/60 border border-slate-800">
            <ScoreGauge score={analysis.overall_score ?? risk.overall_score} label="OVERALL RISK" sublabel={`Confidence: ${((analysis.confidence ?? risk.confidence) * 100).toFixed(0)}%`} />
          </div>
          {Object.entries(risk.sub_scores).map(([name, score]) => (
            <div key={name} className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 flex flex-col justify-between gap-3">
              <div className="flex items-start justify-between gap-2 text-xs"><span className="font-medium text-slate-400 capitalize">{name.replaceAll('_', ' ')}</span><span className="font-mono font-bold text-white">{score}/100</span></div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden"><div className="h-full bg-blue-500" style={{ width: `${score}%` }} /></div>
            </div>
          ))}
        </div>
      </section>

      <InvestigationTimeline result={result} />

      <ProvenanceGraph result={result} />

      <section className="soc-card p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2"><Cpu className="w-5 h-5 text-emerald-400" /><h3 className="text-base font-bold text-white">Multi-engine execution</h3></div>
          <span className="text-[11px] font-mono text-slate-400">{engineAnalysis.orchestrator_version} · public binary uploads: never</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {engineAnalysis.engines.map((engine) => {
            const complete = engine.status === 'completed';
            return (
              <div key={engine.id} className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                <div className="flex items-center justify-between gap-2"><span className="text-xs font-bold text-white">{engine.label}</span><span className={`text-[10px] font-mono font-bold ${complete ? 'text-emerald-400' : engine.status === 'disabled' ? 'text-slate-500' : 'text-amber-400'}`}>{engine.status.toUpperCase()}</span></div>
                <p className="text-[10px] text-slate-500 font-mono">{engine.privacy} · {engine.duration_ms.toFixed(1)} ms</p>
                {engine.error && <p className="text-[10px] text-amber-300">{engine.error}</p>}
              </div>
            );
          })}
        </div>
        <div className="p-3 rounded bg-blue-950/30 border border-blue-500/30 text-xs text-blue-200">
          Reputation: <strong>{engineAnalysis.reputation.verdict}</strong>. {engineAnalysis.reputation.notice}
        </div>
        {engineAnalysis.normalized_findings.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-bold text-slate-300">Normalized optional-engine findings</p>
            {engineAnalysis.normalized_findings.map((finding) => (
              <div key={`${finding.engine}-${finding.id}`} className="p-3 rounded bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div><p className="text-xs font-bold text-white">{finding.title}</p><p className="text-[10px] font-mono text-slate-500">{finding.engine} · {finding.risk_category} · confidence {(finding.confidence * 100).toFixed(0)}%</p></div>
                <span className="text-[10px] font-mono text-orange-300">{finding.score_eligible ? `bounded +${finding.risk_points} evidence points` : 'informational only'}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {aiInvestigation && (
        <section className="soc-card p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2"><CircleHelp className="w-5 h-5 text-violet-300" /><h3 className="text-base font-bold text-white">AI investigator</h3></div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2 py-1 rounded border text-[10px] font-mono font-bold uppercase ${investigationStatusStyle[aiInvestigation.status] ?? investigationStatusStyle.failed}`}>{aiInvestigation.status}</span>
              <span className="text-[11px] font-mono text-slate-400">{aiInvestigation.provider} Â· {aiInvestigation.model} Â· score control: none</span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <p className="text-[10px] uppercase font-bold text-slate-500">Evidence IDs</p>
              <p className="text-2xl font-mono font-bold text-white">{aiInvestigation.evidence_count}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {aiInvestigation.evidence.slice(0, 18).map((item) => (
                  <span key={item.evidence_id} className="px-1.5 py-0.5 rounded border border-slate-700 text-[10px] font-mono text-slate-300" title={`${item.title}: ${item.value}`}>{item.evidence_id}</span>
                ))}
              </div>
            </div>
            <div className="lg:col-span-2 space-y-2">
              {aiInvestigation.warning && <div className="p-3 rounded bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200">{aiInvestigation.warning}</div>}
              {(aiInvestigation.validation_errors ?? []).length > 0 && (
                <div className="p-3 rounded bg-red-950/30 border border-red-500/30 text-xs text-red-200">
                  {(aiInvestigation.validation_errors ?? []).map((error) => <p key={error}>{error}</p>)}
                </div>
              )}
              {aiInvestigation.hypotheses.length === 0 && !aiInvestigation.warning && <p className="text-xs text-slate-400">No evidence-grounded hypotheses were returned.</p>}
            </div>
          </div>

          {aiInvestigation.hypotheses.length > 0 && (
            <div className="space-y-3">
              {aiInvestigation.hypotheses.map((hypothesis) => (
                <div key={hypothesis.hypothesis_id} className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-bold text-white">{hypothesis.title}</p>
                      <p className="text-[10px] font-mono text-slate-500">{hypothesis.category} Â· {hypothesis.status} Â· confidence {(hypothesis.confidence * 100).toFixed(0)}%</p>
                    </div>
                    <span className="text-[10px] font-mono text-violet-300">{hypothesis.hypothesis_id}</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{hypothesis.reasoning_summary}</p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                    <div>
                      <p className="font-bold text-slate-400 mb-1">Supporting IDs</p>
                      <div className="flex flex-wrap gap-1">{hypothesis.supporting_evidence_ids.map((id) => <span key={id} className="font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">{id}</span>)}</div>
                    </div>
                    <div>
                      <p className="font-bold text-slate-400 mb-1">Missing proof</p>
                      <div className="space-y-1 text-slate-300">{hypothesis.missing_evidence.slice(0, 3).map((item) => <p key={item}>{item}</p>)}</div>
                    </div>
                    <div>
                      <p className="font-bold text-slate-400 mb-1">Next experiments</p>
                      <div className="flex flex-wrap gap-1">{hypothesis.recommended_experiment_types.map((item) => <span key={item} className="font-mono px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">{item.replaceAll('_', ' ')}</span>)}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {experimentPlan.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between border-t border-slate-800 pt-4">
                <p className="text-xs font-bold text-slate-300">Safe experiment plan</p>
                <span className="text-[10px] font-mono text-slate-500">{experimentPlan.length} planned records</span>
              </div>
              {experimentPlan.map((experiment) => (
                <div key={experiment.experiment_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-white">{experiment.experiment_type.replaceAll('_', ' ')}</p>
                      <p className="text-[10px] font-mono text-slate-500">{experiment.experiment_id} Â· {experiment.hypothesis_id} Â· priority {experiment.priority} Â· {experiment.timeout_seconds}s</p>
                    </div>
                    <span className={`px-2 py-1 rounded border text-[10px] font-mono font-bold ${experimentStatusStyle[experiment.status] ?? experimentStatusStyle.UNSUPPORTED}`}>{experiment.status}</span>
                  </div>
                  <p className="text-xs text-slate-300">{experiment.objective}</p>
                  <p className="text-[11px] text-slate-400">{experiment.expected_signal}</p>
                  {experiment.unsupported_reason && <p className="text-[11px] text-amber-300">{experiment.unsupported_reason}</p>}
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3"><Shield className="w-5 h-5 text-red-400" /><h3 className="text-base font-bold text-white">Deterministic evidence rules ({risk.evidence.length})</h3></div>
          <div className="space-y-2 max-h-[34rem] overflow-y-auto pr-1">
            {risk.evidence.map((evidence) => (
              <div key={evidence.rule_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <div className="flex items-center justify-between gap-2"><span className="text-xs font-bold text-white">{evidence.title}</span><span className="text-xs font-mono font-bold text-orange-400">+{evidence.points}</span></div>
                <p className="text-xs text-slate-400">{evidence.rationale}</p>
                <p className="text-[10px] font-mono text-slate-500">{evidence.rule_id}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3"><Fingerprint className="w-5 h-5 text-blue-400" /><h3 className="text-base font-bold text-white">Category Fraud Delta</h3></div>
          <div className="flex items-center justify-between"><span className="text-sm text-slate-300">Baseline: {result.fraud_delta.category}</span><span className="font-mono font-bold text-blue-400">{result.fraud_delta.score}</span></div>
          <div className="space-y-2 max-h-[34rem] overflow-y-auto pr-1">
            {result.fraud_delta.contributions.map((contribution, index) => (
              <div key={`${contribution.evidence}-${index}`} className="p-3 rounded bg-slate-950 border border-slate-800"><div className="flex justify-between gap-2"><p className="text-xs font-bold text-red-300">{contribution.evidence}</p><span className="text-xs font-mono text-orange-400">+{contribution.weight}</span></div><p className="text-[11px] text-slate-400 mt-1">{contribution.reason}</p></div>
            ))}
            {result.fraud_delta.contributions.length === 0 && <p className="text-xs text-slate-400">No category-relative anomaly contribution was recorded.</p>}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3"><div className="flex items-center gap-2"><Cpu className="w-5 h-5 text-blue-400" /><h3 className="text-base font-bold text-white">MITRE ATT&amp;CK Mobile</h3></div><span className="text-xs font-mono text-slate-400">{result.mitre_attack.length} mapped</span></div>
          <div className="space-y-2">
            {result.mitre_attack.map((item) => (
              <div key={item.technique_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-2">
                <div><div className="flex items-center gap-2"><span className="font-mono text-xs font-bold text-blue-400">{item.technique_id}</span><span className="text-xs font-bold text-white">{item.name}</span></div><p className="text-[11px] text-slate-400 mt-1">{item.evidence.join(', ')}</p></div>
                <a href={item.source} target="_blank" rel="noreferrer" className="text-slate-400 hover:text-blue-400"><ExternalLink className="w-4 h-4" /></a>
              </div>
            ))}
          </div>
        </div>

        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3"><div className="flex items-center gap-2"><Database className="w-5 h-5 text-cyan-400" /><h3 className="text-base font-bold text-white">Emitted indicators</h3></div><span className="text-xs font-mono text-slate-400">{result.emitted_indicators.length}</span></div>
          <div className="space-y-2">
            {result.emitted_indicators.map((indicator) => (
              <div key={indicator.id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2 font-mono text-xs">
                <div className="min-w-0"><span className="text-[10px] text-slate-500 uppercase">{indicator.type}</span><p className="font-bold text-cyan-300 truncate" title={indicator.display_value}>{indicator.display_value}</p></div>
                <button onClick={() => copyToClipboard(indicator.display_value)} className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300">{copiedValue === indicator.display_value ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}</button>
              </div>
            ))}
            {result.emitted_indicators.length === 0 && <p className="text-xs text-slate-400">No indicator met the high-risk emission threshold.</p>}
          </div>
        </div>
      </section>

      <section className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3"><h3 className="text-base font-bold text-white">Extraction coverage and observed artifacts</h3><span className="text-[11px] font-mono text-slate-400">{result.extraction.engine}</span></div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {Object.entries(result.extraction.coverage).map(([name, covered]) => (
            <div key={name} className="p-2 rounded bg-slate-950 border border-slate-800 text-center"><p className={`text-xs font-bold ${covered ? 'text-emerald-400' : 'text-amber-400'}`}>{covered ? 'COVERED' : 'NOT COVERED'}</p><p className="text-[10px] uppercase text-slate-500 mt-1">{name}</p></div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
          <div className="p-3 rounded bg-slate-950 border border-slate-800"><p className="font-bold text-slate-300 mb-2">Flagged permissions ({result.extraction.permissions.flagged_dangerous.length})</p><div className="flex flex-wrap gap-1">{result.extraction.permissions.flagged_dangerous.map((permission) => <span key={permission} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20">{permission}</span>)}</div></div>
          <div className="p-3 rounded bg-slate-950 border border-slate-800"><p className="font-bold text-slate-300 mb-2">Observed network values ({networkValues.length})</p><div className="space-y-1 font-mono text-[10px] text-cyan-300">{networkValues.map((value) => <p key={value} className="truncate" title={value}>{value}</p>)}</div></div>
        </div>
        {result.extraction.warnings.length > 0 && <div className="p-3 rounded bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200">{result.extraction.warnings.map((warning) => <p key={warning}>• {warning}</p>)}</div>}
      </section>

      <section className="soc-card p-6 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3"><div className="flex items-center gap-2"><FileText className="w-5 h-5 text-purple-400" /><h3 className="text-base font-bold text-white">Analyst narrative</h3></div><span className="text-[11px] font-mono text-slate-400">Source: {result.narrative_metadata.source} · score control: none</span></div>
        <p className="text-sm text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded-lg border border-slate-800 whitespace-pre-wrap">{analysis.narrative ?? 'No narrative is available.'}</p>
      </section>
    </div>
  );
}
