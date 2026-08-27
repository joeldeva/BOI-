import { useState } from 'react';
import type { ApkAnalysisRecord } from '../../types/api';
import { InvestigationHeader } from './InvestigationHeader';
import { ReportTabBar, type ReportTab } from './ReportTabBar';
import { OverviewTab } from './OverviewTab';
import { FingerprintsTab } from './FingerprintsTab';
import { ThreatIntelTab } from './ThreatIntelTab';
import { ApkAnalysisTab } from './ApkAnalysisTab';
import { CodeAnalysisTab } from './CodeAnalysisTab';
import { AiInvestigationTab } from './AiInvestigationTab';
import { BehaviorAnalysisTab } from './BehaviorAnalysisTab';
import { NetworkAnalysisTab } from './NetworkAnalysisTab';
import { FraudDnaTab } from './FraudDnaTab';
import { LoadingState } from '../common/Atoms';
import { ErrorBanner } from '../common/ErrorBanner';
import { apiService } from '../../services/api';

interface InvestigationReportPageProps {
  analysis: ApkAnalysisRecord;
  onBack: () => void;
}

export function InvestigationReportPage({ analysis, onBack }: InvestigationReportPageProps) {
  const [tab, setTab] = useState<ReportTab>('overview');
  const [pdfError, setPdfError] = useState<Error | string | null>(null);
  const [pdfDownloading, setPdfDownloading] = useState(false);

  const handleDownloadPdf = async (id: string) => {
    setPdfError(null);
    setPdfDownloading(true);
    try {
      const blob = await apiService.downloadApkReportPdf(id);
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const baseName = analysis.file_name.replace(/\.apk$/i, '').replace(/[^A-Za-z0-9._-]+/g, '-');
      link.href = blobUrl;
      link.download = `${baseName || id}-investigation-report.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(blobUrl), 0);
    } catch (error) {
      setPdfError(error instanceof Error ? error : 'PDF report download failed.');
    } finally {
      setPdfDownloading(false);
    }
  };

  const handleTabChange = (t: ReportTab) => {
    setTab(t);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const result = analysis.result;

  return (
    <div>
      <div style={{ padding: '9px 0', borderBottom: '1px solid var(--line)', background: 'var(--beige-50)' }}>
        <div style={{ width: 'min(1040px, calc(100% - 32px))', margin: '0 auto' }}>
          <button className="btn btn-secondary btn-sm" onClick={onBack} type="button" id="back-to-investigations">
            ← Investigations
          </button>
        </div>
      </div>

      <InvestigationHeader
        analysis={analysis}
        onDownloadPdf={handleDownloadPdf}
        pdfDownloading={pdfDownloading}
      />
      {pdfError && (
        <div style={{ width: 'min(1040px, calc(100% - 32px))', margin: '14px auto 0' }}>
          <ErrorBanner error={pdfError} onDismiss={() => setPdfError(null)} />
        </div>
      )}
      <ReportTabBar active={tab} onChange={handleTabChange} />

      <div
        className="report-main"
        id={`tabpanel-${tab}`}
        role="tabpanel"
        aria-labelledby={`tab-${tab}`}
      >
        {!result ? (
          <LoadingState lines={6} />
        ) : (
          <>
            {tab === 'overview'     && <OverviewTab result={result} />}
            {tab === 'fingerprints' && <FingerprintsTab result={result} sha256={analysis.sha256} sizeBytes={analysis.size_bytes ?? 0} />}
            {tab === 'intel'        && <ThreatIntelTab result={result} />}
            {tab === 'apk'          && <ApkAnalysisTab result={result} />}
            {tab === 'code'         && <CodeAnalysisTab result={result} />}
            {tab === 'ai'           && <AiInvestigationTab result={result} />}
            {tab === 'behavior'     && <BehaviorAnalysisTab result={result} />}
            {tab === 'network'      && <NetworkAnalysisTab result={result} />}
            {tab === 'frauddna'     && <FraudDnaTab result={result} />}
          </>
        )}
      </div>
    </div>
  );
}
