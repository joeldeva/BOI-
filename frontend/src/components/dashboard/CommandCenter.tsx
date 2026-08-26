import type { ComponentType } from 'react';
import { Activity, ArrowRight, Cpu, Database, ShieldCheck, Smartphone, TriangleAlert, CheckCircle2, XCircle, Clock } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import type {
  HealthResponse,
  DashboardSummaryResponse,
  CapabilitiesResponse,
  ApkAnalysisRecord,
} from '../../types/api';

interface CommandCenterProps {
  health: HealthResponse | null;
  summary: DashboardSummaryResponse | null;
  capabilities: CapabilitiesResponse | null;
  recentApks: ApkAnalysisRecord[];
  onSelectApk: (apkId: string) => void;
  onNavigateTab: (tab: string) => void;
}

function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  color,
  onClick,
}: {
  label: string;
  value: number;
  detail: string;
  icon: ComponentType<{ className?: string }>;
  color: string;
  onClick: () => void;
}) {
  return (
    <button onClick={onClick} className="soc-card soc-card-hover p-5 text-left space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{label}</span>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div className="flex items-baseline justify-between">
        <span className="text-3xl font-display font-extrabold text-white">{value}</span>
        <span className="text-xs text-slate-400 flex items-center gap-1 font-semibold">
          {detail} <ArrowRight className="w-3.5 h-3.5" />
        </span>
      </div>
    </button>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status === 'completed') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
        <CheckCircle2 className="w-3 h-3" /> COMPLETED
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-400 border border-red-500/20">
        <XCircle className="w-3 h-3" /> FAILED
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
      <Clock className="w-3 h-3 animate-spin" /> {status.toUpperCase()}
    </span>
  );
}

export function CommandCenter({
  health,
  summary,
  capabilities,
  recentApks,
  onSelectApk,
  onNavigateTab,
}: CommandCenterProps) {
  const engines = capabilities?.multi_engine.engines ?? [];
  const readyEngines = engines.filter((engine) => engine.enabled && engine.available).length;
  const enabledEngines = engines.filter((engine) => engine.enabled).length;

  return (
    <div className="space-y-6">
      <section className="bg-gradient-to-r from-slate-900 via-slate-900 to-blue-950/40 p-6 rounded-xl border border-slate-800 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        <div className="space-y-2 max-w-3xl">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">DECEPTISCOPE APK INTELLIGENCE</span>
            <span className="text-xs text-slate-400 font-mono">Backend v{health?.version ?? '3.0.0'}</span>
          </div>
          <h1 className="text-2xl font-display font-extrabold text-white tracking-tight">Evidence-grounded Android malware triage</h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            Upload an APK for guarded archive validation, Androguard extraction, bounded local engines, signer checks, optional hash reputation, deterministic risk scoring, MITRE mapping, indicators and a PDF report.
          </p>
          <div className="flex items-center gap-2 text-xs text-amber-300">
            <TriangleAlert className="w-4 h-4 shrink-0" />
            A low score or unknown hash never proves that an APK is legitimate or safe to install.
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="APK analyses" value={summary?.apk_analyses.total ?? 0} detail="Open workspace" icon={Smartphone} color="text-blue-400" onClick={() => onNavigateTab('deceptiscope')} />
        <MetricCard label="Critical results" value={summary?.apk_analyses.critical ?? 0} detail="Review history" icon={TriangleAlert} color="text-red-400" onClick={() => onNavigateTab('deceptiscope')} />
        <MetricCard label="Threat indicators" value={summary?.indicator_count ?? 0} detail="Indicator store" icon={ShieldCheck} color="text-amber-400" onClick={() => onNavigateTab('indicators')} />
        <MetricCard label="Ready engines" value={readyEngines} detail={`${enabledEngines} enabled`} icon={Cpu} color="text-emerald-400" onClick={() => onNavigateTab('deceptiscope')} />
      </section>

      <section className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2"><Cpu className="w-5 h-5 text-blue-400" /><h2 className="text-base font-bold text-white">Live analysis engine matrix</h2></div>
          <span className="text-xs text-slate-400 font-mono">{capabilities?.multi_engine.binary_upload_policy ?? 'loading policy…'}</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {engines.map((engine) => {
            const ready = engine.enabled && engine.available;
            return (
              <div key={engine.id} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-white">{engine.label}</span>
                  <span className={`w-2.5 h-2.5 rounded-full ${ready ? 'bg-emerald-400' : engine.enabled ? 'bg-amber-400' : 'bg-slate-600'}`} />
                </div>
                <p className="text-[10px] font-mono text-slate-500">{engine.id} · {engine.mode}</p>
                <p className={`text-[10px] font-bold ${ready ? 'text-emerald-400' : engine.enabled ? 'text-amber-400' : 'text-slate-500'}`}>
                  {ready ? 'READY' : engine.enabled ? 'OPTIONAL DEPENDENCY MISSING' : 'DISABLED BY POLICY'}
                </p>
              </div>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
          <span className="flex items-center gap-2"><Activity className="w-4 h-4" />Queued: {summary?.jobs.queued ?? 0} · Running: {summary?.jobs.running ?? 0} · Failed: {summary?.jobs.failed ?? 0}</span>
          <span>Database: {capabilities?.database ?? 'unknown'} · Auth: {capabilities?.authentication ?? 'unknown'}</span>
          <span>Public APK upload: never</span>
        </div>
      </section>

      <section className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2"><Database className="w-5 h-5 text-cyan-400" /><h2 className="text-base font-bold text-white">APK Analysis History</h2></div>
          <button onClick={() => onNavigateTab('deceptiscope')} className="text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors">Upload APK →</button>
        </div>
        {recentApks.length === 0 ? (
          <div className="py-12 text-center space-y-2">
            <Smartphone className="w-10 h-10 text-slate-600 mx-auto" />
            <p className="text-sm font-semibold text-slate-300">No APK analyses yet. Upload an APK to begin an investigation.</p>
            <p className="text-xs text-slate-500">Every analyzed sample will persist here for continuous triage and evidence review.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {recentApks.map((apk) => {
              const formattedDate = apk.created_at ? new Date(apk.created_at).toLocaleString() : '—';
              const label = apk.app_name || apk.package_name || apk.file_name;
              return (
                <button
                  key={apk.id}
                  onClick={() => onSelectApk(apk.id)}
                  className="w-full py-3.5 px-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/40 rounded-lg text-left transition-colors group"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="font-semibold text-sm text-white group-hover:text-blue-400 transition-colors truncate max-w-md">
                        {apk.file_name}
                      </span>
                      <StatusBadge status={apk.status} />
                      {apk.category && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-800/80 border border-slate-700/60">
                          {apk.category}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-slate-400 font-mono">
                      {label !== apk.file_name && <span className="text-slate-300 truncate max-w-xs">{label}</span>}
                      <span title={apk.sha256} className="text-slate-500">
                        SHA: {apk.sha256 ? `${apk.sha256.slice(0, 12)}…${apk.sha256.slice(-4)}` : '—'}
                      </span>
                      <span>·</span>
                      <span className="text-slate-500">{formattedDate}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                    {apk.status === 'completed' && (
                      <div className="text-right text-xs font-mono">
                        <div className="text-slate-400 text-[10px]">
                          Static: <span className="text-slate-200 font-bold">{apk.static_score ?? apk.overall_score ?? '—'}</span>
                          {apk.runtime_adjustment ? (
                            <span className="text-amber-400 ml-1">+{apk.runtime_adjustment}</span>
                          ) : null}
                        </div>
                        <div className="font-display font-extrabold text-sm text-white">
                          {apk.overall_score ?? '—'}/100
                        </div>
                      </div>
                    )}
                    <SeverityBadge severity={apk.severity ?? 'LOW'} size="sm" />
                    <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-blue-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
