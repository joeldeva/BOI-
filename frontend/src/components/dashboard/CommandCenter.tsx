import type { ComponentType } from 'react';
import { Activity, ArrowRight, Cpu, Database, ShieldCheck, Smartphone, Sparkles, TriangleAlert } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import { SyntheticBadge } from '../common/SyntheticBadge';
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
  onLaunchDemo: () => void;
  isDemoLoading: boolean;
  onNavigateTab: (tab: string) => void;
  demoEnabled: boolean;
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

export function CommandCenter({
  health,
  summary,
  capabilities,
  recentApks,
  onSelectApk,
  onLaunchDemo,
  isDemoLoading,
  onNavigateTab,
  demoEnabled,
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
        {demoEnabled && (
          <button onClick={onLaunchDemo} disabled={isDemoLoading} className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-bold bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 shadow-lg shadow-amber-500/25 disabled:opacity-50">
            <Sparkles className="w-4 h-4" />
            {isDemoLoading ? 'Creating synthetic evidence…' : 'Run safe synthetic APK demo'}
          </button>
        )}
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
          <div className="flex items-center gap-2"><Database className="w-5 h-5 text-cyan-400" /><h2 className="text-base font-bold text-white">Recent APK analyses</h2></div>
          <button onClick={() => onNavigateTab('deceptiscope')} className="text-xs text-blue-400">Analyze APK →</button>
        </div>
        {recentApks.length === 0 ? <p className="text-sm text-slate-400 py-6 text-center">No APK analyses recorded.</p> : recentApks.slice(0, 8).map((apk) => (
          <button key={apk.id} onClick={() => onSelectApk(apk.id)} className="w-full py-3 px-2 flex items-center justify-between hover:bg-slate-800/50 rounded-lg text-left">
            <div className="min-w-0"><div className="flex items-center gap-2"><span className="font-medium text-sm text-white truncate">{apk.file_name}</span>{apk.data_origin === 'synthetic' && <SyntheticBadge size="sm" />}</div><p className="text-[11px] font-mono text-slate-400">{apk.sha256.slice(0, 16)}… · {apk.analysis_quality ?? apk.status}</p></div>
            <div className="flex items-center gap-3"><SeverityBadge severity={apk.severity ?? 'LOW'} size="sm" /><span className="font-mono font-bold text-sm text-white">{apk.overall_score ?? '—'}/100</span></div>
          </button>
        ))}
      </section>
    </div>
  );
}
