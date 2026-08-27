import { useCallback, useEffect, useRef, useState } from 'react';
import { TopNavigation, type AppPage } from './components/common/TopNavigation';
import { ErrorBanner } from './components/common/ErrorBanner';
import { FraudSearchHero } from './components/home/FraudSearchHero';
import { RecentInvestigationsTable } from './components/home/RecentInvestigationsTable';
import { ApkUploadPanel } from './components/home/ApkUploadPanel';
import { InvestigationReportPage } from './components/report/InvestigationReportPage';
import { SearchPage } from './components/search/SearchPage';
import { CampaignPage } from './components/campaigns/CampaignPage';
import {
  apiService,
  ApiError,
  generateIdempotencyKey,
  pollJob,
  requireJobResourceId,
} from './services/api';
import type {
  CapabilitiesResponse,
  ApkAnalysisRecord,
  JobRecord,
} from './types/api';

const asError = (value: unknown): Error =>
  value instanceof Error ? value : new Error(typeof value === 'string' ? value : 'Unexpected error');

export default function App() {
  const [page, setPage] = useState<AppPage>('home');
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [recentApks, setRecentApks] = useState<ApkAnalysisRecord[]>([]);
  const [selectedApk, setSelectedApk] = useState<ApkAnalysisRecord | null>(null);
  const [loadingApks, setLoadingApks] = useState(true);
  const [isUploadingApk, setIsUploadingApk] = useState(false);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [globalError, setGlobalError] = useState<Error | string | null>(null);
  const [apkJob, setApkJob] = useState<JobRecord | null>(null);
  const apkPoll = useRef<AbortController | null>(null);

  const fetchDashboardData = useCallback(async () => {
    setLoadingApks(true);
    const results = await Promise.allSettled([
      apiService.getCapabilities(),
      apiService.listApkAnalyses(20),
    ] as const);

    const [capabilitiesResult, apksResult] = results;
    if (capabilitiesResult.status === 'fulfilled') setCapabilities(capabilitiesResult.value);
    if (apksResult.status === 'fulfilled') {
      setRecentApks(apksResult.value.items);
    }
    setLoadingApks(false);

    const failure = results.find((result) => result.status === 'rejected');
    if (failure?.status === 'rejected') setGlobalError(asError(failure.reason));
  }, []);

  useEffect(() => {
    void fetchDashboardData();
    return () => apkPoll.current?.abort();
  }, [fetchDashboardData]);

  const handleUploadApk = async (file: File, category: string, dynamic: boolean) => {
    setIsUploadingApk(true);
    setGlobalError(null);
    setApkJob(null);
    apkPoll.current?.abort();
    apkPoll.current = new AbortController();

    // Ensure capabilities are loaded before deciding execution mode
    let currentCaps = capabilities;
    if (!currentCaps) {
      try {
        currentCaps = await apiService.getCapabilities();
        setCapabilities(currentCaps);
      } catch {
        // Fall back to existing behavior if capability check fails
      }
    }

    try {
      if (currentCaps?.inline_analysis) {
        // INLINE MODE: Analyze APK immediately via POST /api/v1/apk-analyses
        const result = await apiService.analyzeApkInline(
          { file, category, dynamic },
          apkPoll.current.signal
        );
        setSelectedApk(result);
        setPage('report');
        await fetchDashboardData();
      } else {
        // DURABLE JOB MODE: Create job and poll
        const queued = await apiService.submitApkJob({
          file,
          category: category as 'banking' | 'finance' | 'utility' | 'other',
          dynamic,
          idempotencyKey: generateIdempotencyKey(),
        });
        setApkJob(queued);
        const completed = queued.status === 'completed'
          ? queued
          : await pollJob(queued.id, setApkJob, 10 * 60_000, apkPoll.current.signal);
        if (completed.status === 'failed') {
          throw new ApiError(completed.error_message || 'APK analysis job failed', completed.error_code || 'job_failed', 500);
        }
        if (completed.status === 'cancelled') {
          throw new ApiError('APK analysis job was cancelled', 'job_cancelled', 409);
        }
        const result = await apiService.getApkAnalysis(requireJobResourceId(completed, 'apk_analysis'));
        setSelectedApk(result);
        setPage('report');
        await fetchDashboardData();
      }
    } catch (error) {
      setGlobalError(asError(error));
      throw error;
    } finally {
      setIsUploadingApk(false);
    }
  };

  const handleOpenReport = async (id: string) => {
    try {
      const record = await apiService.getApkAnalysis(id);
      setSelectedApk(record);
      setPage('report');
      window.scrollTo(0, 0);
    } catch (err) {
      setGlobalError(asError(err));
    }
  };

  const handleSearch = (query: string) => {
    const matched = recentApks.find(a =>
      a.file_name.toLowerCase().includes(query.toLowerCase()) ||
      a.package_name?.toLowerCase().includes(query.toLowerCase()) ||
      a.app_name?.toLowerCase().includes(query.toLowerCase()) ||
      a.sha256.toLowerCase().includes(query.toLowerCase())
    );
    if (matched) {
      void handleOpenReport(matched.id);
    } else {
      setPage('search');
    }
  };

  return (
    <div>
      <TopNavigation
        page={page}
        onNavigate={(p) => { setPage(p); window.scrollTo(0, 0); }}
        capabilities={capabilities}
      />

      {globalError && (
        <div style={{ width: 'min(1180px, calc(100% - 28px))', margin: '14px auto 0' }}>
          <ErrorBanner error={globalError} onDismiss={() => setGlobalError(null)} />
        </div>
      )}

      {page === 'home' && (
        <>
          <FraudSearchHero
            onSearch={handleSearch}
            onOpenUpload={() => setIsUploadModalOpen(true)}
            capabilities={capabilities}
          />
          <main className="main">
            <RecentInvestigationsTable
              analyses={recentApks}
              loading={loadingApks}
              onOpen={handleOpenReport}
            />
          </main>
        </>
      )}

      {page === 'investigations' && (
        <main className="main">
          <RecentInvestigationsTable
            analyses={recentApks}
            loading={loadingApks}
            onOpen={handleOpenReport}
          />
        </main>
      )}

      {page === 'search' && <SearchPage />}

      {page === 'campaigns' && (
        <CampaignPage
          recentApks={recentApks}
          onOpenReport={handleOpenReport}
        />
      )}

      {page === 'report' && selectedApk && (
        <InvestigationReportPage
          analysis={selectedApk}
          onBack={() => setPage('investigations')}
        />
      )}

      <ApkUploadPanel
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onUpload={handleUploadApk}
        isUploading={isUploadingApk}
        capabilities={capabilities}
        jobStatus={apkJob?.status ?? null}
        jobId={apkJob?.id ?? null}
        jobError={apkJob?.error_message ?? null}
      />
    </div>
  );
}
