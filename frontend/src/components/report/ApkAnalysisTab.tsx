import { useState } from 'react';
import type { ApkAnalysisResult } from '../../types/api';
import { StatusPillAuto } from '../common/StatusPill';
import { EmptyState } from '../common/Atoms';

type ComponentTab = 'permissions' | 'activities' | 'services' | 'receivers' | 'providers' | 'native';

interface ApkAnalysisTabProps { result: ApkAnalysisResult; }

export function ApkAnalysisTab({ result }: ApkAnalysisTabProps) {
  const [tab, setTab] = useState<ComponentTab>('permissions');
  const ext = result.extraction;
  const comps = ext.components;
  const nativeLibs = (comps as unknown as Record<string, unknown>).native_libraries as string[] | undefined;

  return (
    <div>
      <h2 className="section-title">APK analysis</h2>

      <div className="card padded" style={{ marginBottom: 22 }}>
        <table className="kv-table">
          <tbody>
            <tr><td>Package name</td><td>{ext.app.package_name ?? '—'}</td></tr>
            <tr><td>Min SDK / target SDK</td><td>{ext.app.min_sdk ?? '—'} / {ext.app.target_sdk ?? '—'}</td></tr>
            <tr><td>Analysis quality</td><td>{ext.analysis_quality}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="analysis-tabs" role="tablist">
        {(['permissions','activities','services','receivers','providers','native'] as ComponentTab[]).map(t => (
          <button
            key={t}
            className={`small-tab${tab === t ? ' active' : ''}`}
            onClick={() => setTab(t)}
            role="tab"
            aria-selected={tab === t}
            type="button"
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'permissions' && (
        ext.permissions.requested.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table" aria-label="Requested permissions">
              <thead><tr><th>Permission</th><th>Risk</th></tr></thead>
              <tbody>
                {ext.permissions.requested.map(p => (
                  <tr key={p} className="no-hover">
                    <td className="hash">{p}</td>
                    <td><StatusPillAuto value={ext.permissions.flagged_dangerous.includes(p) ? 'HIGH' : 'LOW'} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No permissions declared" />
      )}

      {tab === 'activities' && (
        comps.activities.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table" aria-label="Activities">
              <thead><tr><th>Name</th></tr></thead>
              <tbody>
                {comps.activities.map(c => (
                  <tr key={c} className="no-hover">
                    <td className="hash">{c}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No activities" />
      )}

      {tab === 'services' && (
        comps.services.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table" aria-label="Services">
              <thead><tr><th>Name</th></tr></thead>
              <tbody>
                {comps.services.map(c => (
                  <tr key={c} className="no-hover">
                    <td className="hash">{c}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No services" />
      )}

      {tab === 'receivers' && (
        comps.receivers.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table" aria-label="Receivers">
              <thead><tr><th>Name</th></tr></thead>
              <tbody>
                {comps.receivers.map(c => (
                  <tr key={c} className="no-hover">
                    <td className="hash">{c}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No receivers" />
      )}

      {tab === 'providers' && (
        comps.providers.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table" aria-label="Content providers">
              <thead><tr><th>Name</th></tr></thead>
              <tbody>
                {comps.providers.map(c => (
                  <tr key={c} className="no-hover"><td className="hash">{c}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No content providers" />
      )}

      {tab === 'native' && (
        nativeLibs && nativeLibs.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table" aria-label="Native libraries">
              <thead><tr><th>Library</th></tr></thead>
              <tbody>
                {nativeLibs.map((lib: string) => (
                  <tr key={lib} className="no-hover"><td className="hash">{lib}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No native libraries" />
      )}

      {ext.warnings && ext.warnings.length > 0 && (
        <>
          <h3 className="subsection-title">Extraction warnings & anomalies</h3>
          <div className="card padded">
            {ext.warnings.map((w, i) => (
              <div key={i} style={{ padding: '7px 0', borderBottom: i < ext.warnings.length - 1 ? '1px solid var(--line)' : undefined }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{w}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
