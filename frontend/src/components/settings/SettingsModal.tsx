import React, { useState } from 'react';
import { X, CheckCircle, AlertCircle, RefreshCw } from 'lucide-react';
import { apiService } from '../../services/api';
import type { CapabilitiesResponse } from '../../types/api';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  capabilities: CapabilitiesResponse | null;
  onRefreshCapabilities: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  capabilities,
  onRefreshCapabilities,
}) => {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

  if (!isOpen) return null;

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const health = await apiService.getHealth();
      setTestResult({
        ok: true,
        msg: `Connected successfully to FraudShield Backend v${health.version} (Database: ${health.database})`,
      });
      onRefreshCapabilities();
    } catch (err: any) {
      setTestResult({
        ok: false,
        msg: err.message || 'Connection test failed',
      });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl space-y-4 p-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-base font-bold text-white">Platform Settings & Architecture</h3>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4 text-xs">
          <div className="space-y-1.5">
            <label className="font-semibold text-slate-300">Backend API Base Endpoint:</label>
            <input
              type="text"
              readOnly
              value={apiService.baseUrl}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-300 font-mono"
            />
            <p className="text-[11px] text-slate-500">
              Configured via non-secret environment variable <code className="text-blue-400 font-mono">VITE_API_BASE_URL</code>.
            </p>
          </div>

          {capabilities && (
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 rounded bg-slate-950 border border-slate-800"><span className="text-slate-500">Authentication</span><p className="font-mono text-slate-200">{capabilities.authentication}</p></div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800"><span className="text-slate-500">Database adapter</span><p className="font-mono text-slate-200">{capabilities.database}</p></div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800"><span className="text-slate-500">Durable jobs</span><p className="font-mono text-slate-200">{String(capabilities.durable_jobs)}</p></div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800"><span className="text-slate-500">Audit chain</span><p className="font-mono text-slate-200">{String(capabilities.tamper_evident_audit)}</p></div>
            </div>
          )}

          {/* Bank Security Architecture Note */}
          <div className="p-3 rounded bg-blue-950/30 border border-blue-500/30 text-blue-200 space-y-1">
            <span className="font-bold text-blue-300 uppercase text-[10px] tracking-wider">
              BANK ENTERPRISE SECURITY ARCHITECTURE
            </span>
            <p className="text-[11px] leading-relaxed text-blue-200/90">
              No service API keys are stored in frontend bundles or local storage. In production, API gateway authentication & session tokens are managed strictly by a bank-controlled proxy/BFF.
            </p>
          </div>

          {/* Test Connection Button */}
          <div className="flex items-center justify-between pt-2">
            <button
              onClick={handleTestConnection}
              disabled={testing}
              className="flex items-center gap-2 px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-white font-bold disabled:opacity-50"
            >
              {testing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
              Test Backend Connection
            </button>
          </div>

          {testResult && (
            <div
              className={`p-3 rounded border text-xs flex items-center gap-2 ${
                testResult.ok
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  : 'bg-red-950/40 border-red-500/40 text-red-300'
              }`}
            >
              {testResult.ok ? (
                <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              )}
              <span>{testResult.msg}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
