import { useState, useRef } from 'react';
import { Upload, X } from 'lucide-react';
import type { CapabilitiesResponse } from '../../types/api';
import { isRuntimeReady } from '../../utils/analysisTruth.mjs';

interface ApkUploadPanelProps {
  isOpen: boolean;
  onClose: () => void;
  onUpload: (file: File, category: string, dynamic: boolean) => Promise<void>;
  isUploading: boolean;
  capabilities: CapabilitiesResponse | null;
  jobStatus: string | null;
  jobId: string | null;
  jobError: string | null;
}

function formatBytes(b: number): string {
  if (!b) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), 3);
  return `${(b / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function ApkUploadPanel({
  isOpen, onClose, onUpload,
  isUploading, capabilities, jobStatus, jobId, jobError,
}: ApkUploadPanelProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [category, setCategory] = useState('banking');
  const [dynamic, setDynamic] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const dynamicAvailable = isRuntimeReady(capabilities);

  const handleFile = (f: File | undefined) => {
    if (!f) return;
    if (!f.name.toLowerCase().endsWith('.apk')) {
      setError('Please choose an .apk file');
      return;
    }
    setError(null);
    setSelectedFile(f);
  };

  const handleSubmit = async () => {
    if (!selectedFile || isUploading) return;
    setError(null);
    try {
      await onUpload(selectedFile, category, dynamic);
      setSelectedFile(null);
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || 'Analysis failed');
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Upload APK"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal">
        <div className="modal-head">
          <div>
            <div className="modal-title">Upload suspicious APK</div>
            <div className="modal-copy">Guarded ingestion. Analysis runs on the real pipeline — no fabricated results.</div>
          </div>
          <button className="close-x" onClick={onClose} aria-label="Close" type="button"><X size={18} /></button>
        </div>
        <div className="modal-body">
          <div
            className="dropzone"
            style={dragOver ? { borderColor: 'var(--brand-500)', background: 'var(--brand-100)' } : {}}
            onClick={() => !isUploading && fileInputRef.current?.click()}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]); }}
            role="button"
            aria-label="Choose or drop an APK file"
            tabIndex={0}
            onKeyDown={e => { if (e.key === 'Enter') fileInputRef.current?.click(); }}
          >
            <Upload size={28} style={{ margin: '0 auto' }} />
            <strong>{selectedFile ? selectedFile.name : 'Choose or drop an APK'}</strong>
            {selectedFile ? (
              <span>{formatBytes(selectedFile.size)} · {category}</span>
            ) : (
              <span>APK only</span>
            )}
            <input
              ref={fileInputRef}
              id="apk-file-input"
              type="file"
              accept=".apk"
              style={{ display: 'none' }}
              onChange={e => handleFile(e.target.files?.[0])}
              aria-label="Select APK file"
            />
          </div>

          {error && <p className="error-notice" style={{ marginTop: 10 }}>{error}</p>}

          <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <label htmlFor="apk-category" style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)' }}>Category</label>
              <select
                id="apk-category"
                value={category}
                onChange={e => setCategory(e.target.value)}
                style={{ height: 34, border: '1px solid var(--line)', borderRadius: 6, padding: '0 10px', fontSize: 13 }}
              >
                <option value="banking">Banking</option>
                <option value="finance">Finance</option>
                <option value="utility">Utility</option>
                <option value="other">Other</option>
              </select>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: dynamicAvailable ? 'pointer' : 'default' }}>
              <input
                type="checkbox"
                id="apk-dynamic"
                checked={dynamic}
                onChange={e => setDynamic(e.target.checked)}
                disabled={!dynamicAvailable}
              />
              <span style={{ color: dynamicAvailable ? 'var(--ink)' : 'var(--muted)' }}>
                Enable dynamic analysis
                {!dynamicAvailable && ' (runtime unavailable)'}
              </span>
            </label>
          </div>

          {(isUploading || jobStatus) && (
            <div className="job-progress">
              <span style={{ fontWeight: 600 }}>
                {capabilities?.inline_analysis
                  ? (isUploading ? 'Analyzing…' : 'Analysis complete')
                  : (jobStatus === 'queued' ? 'Queued / Waiting for analysis worker' :
                     jobStatus === 'running' ? 'Analyzing…' :
                     jobStatus === 'completed' ? 'Analysis complete' :
                     jobStatus === 'failed' ? 'Failed' :
                     'Submitting…')}
              </span>
              {!capabilities?.inline_analysis && jobId && (
                <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>{jobId}</span>
              )}
              {jobError && <p style={{ color: 'var(--danger)', fontSize: 12, marginTop: 4 }}>{jobError}</p>}
              <div className="job-progress-bar">
                <div className={`job-progress-fill${(isUploading || jobStatus === 'running' || jobStatus === 'queued') ? ' indeterminate' : ''}`}
                  style={(isUploading || jobStatus === 'running' || jobStatus === 'queued') ? {} : { width: jobStatus === 'completed' ? '100%' : '0%' }} />
              </div>
            </div>
          )}

          <div className="modal-actions">
            <button className="btn btn-secondary" onClick={onClose} type="button" disabled={isUploading}>Cancel</button>
            <button
              className="btn btn-primary"
              onClick={() => void handleSubmit()}
              type="button"
              disabled={!selectedFile || isUploading || Boolean(jobStatus === 'queued' || jobStatus === 'running')}
              id="begin-investigation-btn"
            >
              {capabilities?.inline_analysis
                ? (isUploading ? 'Analyzing…' : 'Begin investigation')
                : (jobStatus === 'queued' ? 'Queued…' : isUploading || jobStatus === 'running' ? 'Analyzing…' : 'Begin investigation')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
