import { Download, Smartphone } from 'lucide-react';
import { StatusPillAuto } from '../common/StatusPill';
import type { ApkAnalysisRecord } from '../../types/api';

interface InvestigationHeaderProps {
  analysis: ApkAnalysisRecord;
  onDownloadPdf: (id: string) => void;
}

function verdictLabel(a: ApkAnalysisRecord): string {
  const v = a.result?.malware_assessment?.verdict;
  if (!v) return a.severity ?? 'UNKNOWN';
  return String(v).replace(/_/g, ' ');
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function InvestigationHeader({ analysis, onDownloadPdf }: InvestigationHeaderProps) {
  const result = analysis.result;
  const ext = result?.extraction;
  const risk = result?.risk;
  const ai = result?.ai_investigation;

  const perms = ext?.permissions.requested.length ?? 0;
  const activities = ext?.components.activities.length ?? 0;
  const services = ext?.components.services.length ?? 0;
  const receivers = ext?.components.receivers.length ?? 0;
  const domains = (ext?.network_indicators.domains.length ?? 0) +
                  (ext?.network_indicators.ips.length ?? 0);
  const hypotheses = ai?.hypotheses.length ?? 0;

  const finalScore = analysis.overall_score ?? risk?.overall_score ?? null;
  const severity = analysis.severity ?? risk?.severity ?? null;
  const isMalicious = severity === 'CRITICAL' || severity === 'HIGH';

  return (
    <section className="report-hero" aria-label="Investigation summary">
      <div className="report-hero-inner">
        <div className="report-heading">
          <div className="verdict">
            <div className="verdict-label">{verdictLabel(analysis)}</div>
            <div className="verdict-score">
              {finalScore ?? '—'}<span>/100</span>
            </div>
            <div className="verdict-caption">Banking fraud risk</div>
            <button
              className="btn btn-secondary btn-sm"
              style={{ marginTop: 10 }}
              onClick={() => onDownloadPdf(analysis.id)}
              type="button"
              id="download-report-pdf"
            >
              <Download size={12} style={{ display: 'inline', marginRight: 4 }} />
              PDF report
            </button>
          </div>

          <div className="app-identity">
            <div className="app-icon" aria-hidden="true">
              <Smartphone size={28} strokeWidth={1.6} />
            </div>
            <div>
              <div className="app-package">{ext?.app.package_name ?? analysis.package_name ?? analysis.file_name}</div>
              <div className="app-name">{ext?.app.app_label ?? analysis.app_name ?? ''}</div>
              <div className="app-meta">
                {analysis.file_name}
                {analysis.completed_at ? ` · analyzed ${formatDate(analysis.completed_at)}` : ''}
              </div>
            </div>
          </div>

          <div className="risk-box">
            <div className="risk-main" style={{ color: isMalicious ? 'var(--danger)' : 'var(--amber)' }}>
              {finalScore ?? '—'}<span>/100</span>
            </div>
            <div className="risk-severity">
              {severity && <StatusPillAuto value={severity} />}
            </div>
            <div style={{ fontSize: 11, color: '#777', marginTop: 8 }}>
              Static {analysis.static_score ?? risk?.static_score ?? '—'}
              {' · '}
              Runtime +{analysis.runtime_adjustment ?? risk?.runtime_adjustment ?? 0}
            </div>
          </div>
        </div>

        <div className="metric-strip">
          {[
            { value: perms, label: 'permissions' },
            { value: activities, label: 'activities' },
            { value: services, label: 'services' },
            { value: receivers, label: 'receivers' },
            { value: domains, label: 'domains / IPs' },
            { value: hypotheses, label: 'AI hypotheses' },
          ].map(({ value, label }) => (
            <div key={label} className="metric-box">
              <div className="metric-value">{result ? value : '—'}</div>
              <div className="metric-label">{label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
