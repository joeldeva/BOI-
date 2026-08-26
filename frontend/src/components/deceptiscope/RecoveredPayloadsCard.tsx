import { Layers } from 'lucide-react';
import type { RecoveredPayload } from '../../types/api';

interface RecoveredPayloadsCardProps {
  payloads?: RecoveredPayload[];
}

export function RecoveredPayloadsCard({ payloads }: RecoveredPayloadsCardProps) {
  if (!payloads || payloads.length === 0) {
    return null;
  }

  return (
    <section className="soc-card p-6 space-y-4" data-testid="recovered-payloads-section">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-amber-400" />
          <h3 className="text-base font-bold text-white">Recovered Payloads ({payloads.length})</h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Recursive Static Reverse Engineering · No Dynamic Re-execution
        </span>
      </div>

      <div className="space-y-4">
        {payloads.map((payload) => {
          const isAnalyzed = payload.analysis_status === 'ANALYZED';
          return (
            <div
              key={payload.payload_id}
              className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {payload.payload_id}
                  </span>
                  <span className="text-xs font-bold text-white uppercase font-mono">
                    {payload.payload_type} ({payload.source})
                  </span>
                  <span className="text-xs text-slate-400">
                    via <code className="text-blue-300 font-mono">{payload.loader}</code>
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs font-mono">
                  <span className="text-slate-400">{(payload.size_bytes / 1024).toFixed(1)} KB</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isAnalyzed
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {payload.analysis_status}
                  </span>
                </div>
              </div>

              <div className="text-xs font-mono text-slate-400 break-all">
                SHA-256: <span className="text-slate-200">{payload.sha256}</span>
              </div>

              {payload.extracted_capabilities && payload.extracted_capabilities.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    Newly Discovered Secondary Capabilities
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {payload.extracted_capabilities.map((cap) => (
                      <span
                        key={cap}
                        className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/15 text-red-300 border border-red-500/30"
                      >
                        {cap.replaceAll('_', ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {payload.method_level_evidence && payload.method_level_evidence.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    Extracted Method Signatures ({payload.method_level_evidence.length})
                  </p>
                  <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                    {payload.method_level_evidence.slice(0, 5).map((mth: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-slate-900/80 border border-slate-800 text-[11px] flex items-center justify-between gap-2"
                      >
                        <span className="text-slate-300 truncate">
                          <strong className="text-amber-300">{mth.signature_id}</strong>: {mth.title}
                        </span>
                        <code className="text-slate-500 font-mono text-[10px] shrink-0">
                          {mth.class_name ? `${mth.class_name}->${mth.method_name}` : ''}
                        </code>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
