import React, { useState } from 'react';
import { X, Database } from 'lucide-react';
import { apiService } from '../../services/api';
import type { SeverityLevel, ThreatIndicatorRecord } from '../../types/api';

interface NewIndicatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (newIndicator: ThreatIndicatorRecord) => void;
}

export const NewIndicatorModal: React.FC<NewIndicatorModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [type, setType] = useState('ip');
  const [value, setValue] = useState('');
  const [confidence, setConfidence] = useState(85);
  const [severity, setSeverity] = useState<SeverityLevel>('HIGH');
  const [source, setSource] = useState('analyst_manual');
  const [context, setContext] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) {
      setError('Indicator value is required.');
      return;
    }
    setError(null);
    setIsSubmitting(true);

    try {
      const created = await apiService.createIndicator({
        type,
        value: value.trim(),
        confidence: confidence / 100,
        severity,
        description: context.trim() || 'Manually registered by an analyst; validate before enforcement.',
        metadata: { source: source.trim() || 'analyst_manual' },
      });
      onSuccess(created);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to register threat indicator');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl space-y-4 p-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-blue-400" />
            <h3 className="text-base font-bold text-white">Register Threat Indicator</h3>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="p-3 rounded bg-red-950/40 border border-red-800 text-xs text-red-300">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="space-y-1">
              <label className="font-semibold text-slate-300">Indicator Type:</label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
              >
                <option value="ip">IPv4 / IPv6 Address</option>
                <option value="domain">Domain Name</option>
                <option value="url">C2 URL</option>
                <option value="package">Android Package Name</option>
                <option value="sha256">File SHA-256 Hash</option>
                <option value="account">Bank / UPI VPA Account</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="font-semibold text-slate-300">Severity:</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value as SeverityLevel)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono">
                <option value="LOW">LOW</option><option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="font-semibold text-slate-300">Confidence (0 - 100%):</label>
              <input
                type="number"
                min={0}
                max={100}
                value={confidence}
                onChange={(e) => setConfidence(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-slate-300">Indicator Value:</label>
            <input
              type="text"
              placeholder="e.g. 198.51.100.42 or c2.trojan.invalid"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
            />
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-slate-300">Source Tag:</label>
            <input
              type="text"
              placeholder="e.g. deceptiscope_extracted or analyst_manual"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
            />
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-slate-300">Context / Notes:</label>
            <textarea
              rows={2}
              placeholder="Optional investigation context..."
              value={context}
              onChange={(e) => setContext(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-sans"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded text-slate-300 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold disabled:opacity-50"
            >
              {isSubmitting ? 'Registering...' : 'Register Indicator'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
