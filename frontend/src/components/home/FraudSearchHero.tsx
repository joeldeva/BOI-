import { useState, useRef } from 'react';
import { Shield, Search, Upload } from 'lucide-react';
import type { CapabilitiesResponse } from '../../types/api';

interface FraudSearchHeroProps {
  onSearch: (query: string) => void;
  onOpenUpload: () => void;
  capabilities: CapabilitiesResponse | null;
}

export function FraudSearchHero({ onSearch, onOpenUpload, capabilities }: FraudSearchHeroProps) {
  const [mode, setMode] = useState<'search' | 'upload'>('search');
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = () => {
    const q = query.trim();
    if (q) onSearch(q);
  };

  const keyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') submit();
  };

  const hasFraudDna = !!(capabilities?.dynamic_lite);
  const dimensions = [
    'SHA256', 'package name', 'app name',
    hasFraudDna ? 'campaign' : null,
    'domain', 'IP',
  ].filter(Boolean).join(', ');

  return (
    <section className="hero" aria-label="FraudShield search">
      <div className="hero-inner">
        <h1>Mobile fraud intelligence for banking</h1>
        <p className="hero-sub">
          Generative AI-powered reverse engineering, runtime validation and fraud campaign intelligence
        </p>
        <div className="hero-logo" aria-hidden="true">
          <Shield size={62} strokeWidth={1.4} />
        </div>

        <div className="hero-tabs" role="tablist">
          <button
            className={`hero-tab${mode === 'search' ? ' active' : ''}`}
            onClick={() => { setMode('search'); window.setTimeout(() => inputRef.current?.focus(), 50); }}
            role="tab"
            aria-selected={mode === 'search'}
            type="button"
          >
            Search
          </button>
          <button
            className={`hero-tab${mode === 'upload' ? ' active' : ''}`}
            onClick={() => setMode('upload')}
            role="tab"
            aria-selected={mode === 'upload'}
            type="button"
          >
            File
          </button>
        </div>

        {mode === 'search' ? (
          <>
            <div className="search-shell" role="search">
              <label htmlFor="global-search" className="sr-only">Search investigations</label>
              <input
                id="global-search"
                ref={inputRef}
                className="search-input"
                placeholder="SHA256, package, app name, domain, IP or campaign"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={keyDown}
                autoComplete="off"
                spellCheck={false}
              />
              <button
                className="search-button"
                onClick={submit}
                aria-label="Search"
                type="button"
              >
                <Search size={18} strokeWidth={1.8} />
              </button>
            </div>
            <p className="hero-help">
              Search uploaded investigations, FraudDNA campaigns, IOCs and fingerprints.<br />
              <strong>Supported dimensions:</strong> {dimensions}
            </p>
          </>
        ) : (
          <div className="upload-box">
            <strong>Upload suspicious Android APK</strong>
            <p>Guarded ingestion · static analysis · AI investigator · trusted runtime experiments · deterministic risk scoring</p>
            <div className="upload-cta">
              <button
                className="btn btn-primary"
                onClick={onOpenUpload}
                type="button"
                id="open-upload-btn"
              >
                <Upload size={14} style={{ display: 'inline', marginRight: 6 }} />
                Select APK
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
