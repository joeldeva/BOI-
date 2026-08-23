import { useCallback, useEffect, useMemo, useState } from 'react';
import { Check, Copy, Database, Plus, RefreshCw, Search } from 'lucide-react';
import { NewIndicatorModal } from './NewIndicatorModal';
import { apiService } from '../../services/api';
import { SeverityBadge } from '../common/SeverityBadge';
import type { ThreatIndicatorRecord } from '../../types/api';

interface IndicatorStoreProps { onError: (error: Error) => void; }

export function IndicatorStore({ onError }: IndicatorStoreProps) {
  const [indicators, setIndicators] = useState<ThreatIndicatorRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchIndicators = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await apiService.listIndicators(200);
      setIndicators(response.items);
    } catch (error) {
      onError(error instanceof Error ? error : new Error('Could not load threat indicators'));
    } finally {
      setIsLoading(false);
    }
  }, [onError]);

  useEffect(() => { void fetchIndicators(); }, [fetchIndicators]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return indicators.filter((item) => {
      const searchable = `${item.display_value} ${item.normalized_value} ${item.description} ${JSON.stringify(item.metadata)}`.toLowerCase();
      return (!query || searchable.includes(query)) && (typeFilter === 'all' || item.type === typeFilter);
    });
  }, [indicators, search, typeFilter]);

  const handleCopy = async (item: ThreatIndicatorRecord) => {
    await navigator.clipboard.writeText(item.normalized_value);
    setCopiedId(item.id);
    window.setTimeout(() => setCopiedId(null), 2_000);
  };

  return (
    <div className="space-y-6">
      <section className="soc-card p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2"><Database className="w-5 h-5 text-cyan-400" /><h2 className="text-xl font-display font-extrabold text-white">Threat Indicator Store</h2></div>
          <p className="text-xs text-slate-400 mt-1">Persistent normalized registry linking APK evidence to analyst-reviewed threat intelligence.</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => void fetchIndicators()} disabled={isLoading} className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300" title="Refresh indicators"><RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} /></button>
          <button onClick={() => setIsModalOpen(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white"><Plus className="w-4 h-4" />Register indicator</button>
        </div>
      </section>

      <div className="flex flex-col sm:flex-row items-center gap-3">
        <label className="relative flex-1 w-full">
          <span className="sr-only">Search indicators</span><Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input type="search" placeholder="Search values, descriptions, or metadata…" value={search} onChange={(event) => setSearch(event.target.value)} className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white" />
        </label>
        <select aria-label="Indicator type" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="w-full sm:w-48 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white">
          <option value="all">All types</option><option value="ip">IP addresses</option><option value="domain">Domains</option><option value="url">URLs</option><option value="package">Package names</option><option value="sha256">SHA-256 hashes</option><option value="certificate_sha256">Certificate hashes</option>
        </select>
      </div>

      <section className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono"><tr><th className="py-3 px-4">Indicator value</th><th className="py-3 px-4">Type</th><th className="py-3 px-4">Severity</th><th className="py-3 px-4">Confidence</th><th className="py-3 px-4">Sightings</th><th className="py-3 px-4 text-right">Copy</th></tr></thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.length === 0 ? <tr><td colSpan={6} className="py-8 text-center text-slate-500 font-sans">{isLoading ? 'Loading threat indicators…' : 'No matching threat indicators found.'}</td></tr> : filtered.map((item) => (
                <tr key={item.id} className="hover:bg-slate-800/40">
                  <td className="py-3 px-4"><p className="font-bold text-cyan-300 max-w-md truncate" title={item.display_value}>{item.display_value}</p><p className="text-[10px] text-slate-500 font-sans max-w-md truncate">{item.description}</p></td>
                  <td className="py-3 px-4 uppercase text-slate-300">{item.type}</td>
                  <td className="py-3 px-4"><SeverityBadge severity={item.severity} size="sm" /></td>
                  <td className="py-3 px-4 text-emerald-400 font-bold">{Math.round(item.confidence * 100)}%</td>
                  <td className="py-3 px-4 text-slate-300">{item.sightings_count}</td>
                  <td className="py-3 px-4 text-right"><button onClick={() => void handleCopy(item)} className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300" title="Copy normalized value">{copiedId === item.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <NewIndicatorModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} onSuccess={(created) => setIndicators((current) => [created, ...current.filter((item) => item.id !== created.id)])} />
    </div>
  );
}
