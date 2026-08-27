import type { ApkAnalysisRecord } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { LoadingState, EmptyState } from '../common/Atoms';
import { severityFromScore } from '../../utils/analysisTruth.mjs';

interface RecentInvestigationsTableProps {
  analyses: ApkAnalysisRecord[];
  loading: boolean;
  onOpen: (id: string) => void;
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function riskLabel(a: ApkAnalysisRecord): string {
  if (a.severity) return a.severity;
  const s = a.overall_score;
  if (s === null) return a.status.toUpperCase();
  return severityFromScore(s);
}

export function RecentInvestigationsTable({ analyses, loading, onOpen }: RecentInvestigationsTableProps) {
  return (
    <section aria-labelledby="recent-investigations-title">
      <h2 id="recent-investigations-title" className="section-title">Recent investigations</h2>
      {loading ? (
        <LoadingState lines={4} />
      ) : analyses.length === 0 ? (
        <EmptyState
          title="No APK analyses yet."
          message="Upload an APK to begin an investigation."
        />
      ) : (
        <div className="table-wrap">
          <table className="data-table" aria-label="Recent APK investigations">
            <thead>
              <tr>
                <th scope="col">App name</th>
                <th scope="col">Package name</th>
                <th scope="col">SHA256</th>
                <th scope="col">Final risk</th>
                <th scope="col">Analyzed</th>
              </tr>
            </thead>
            <tbody>
              {analyses.map(a => (
                <tr
                  key={a.id}
                  onClick={() => onOpen(a.id)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onOpen(a.id); }}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open investigation: ${a.file_name}`}
                >
                  <td>
                    <strong>{a.app_name ?? a.file_name}</strong>
                    {a.app_name && (
                      <div style={{ fontSize: 11, color: '#777', marginTop: 2 }}>{a.file_name}</div>
                    )}
                  </td>
                  <td>{a.package_name ?? '—'}</td>
                  <td className="hash">
                    {a.sha256.slice(0, 16)}…{a.sha256.slice(-8)}
                  </td>
                  <td><StatusPillAuto value={riskLabel(a)} /></td>
                  <td>{formatDate(a.completed_at ?? a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="notice" style={{ marginTop: 16 }}>
        FraudShield reports are evidence-grounded. AI can propose hypotheses,
        but confirmed banking behaviors require deterministic technical verification.
      </div>
    </section>
  );
}
