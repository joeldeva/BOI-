import { Shield, Home, Search, FileText, Dna, Info } from 'lucide-react';
import type { CapabilitiesResponse } from '../../types/api';

export type AppPage = 'home' | 'search' | 'investigations' | 'campaigns' | 'report';

interface TopNavigationProps {
  page: AppPage;
  onNavigate: (page: AppPage) => void;
  capabilities: CapabilitiesResponse | null;
}

function getRuntimeStatus(capabilities: CapabilitiesResponse | null) {
  if (capabilities === null) return { label: '…', ready: false, loading: true };
  const dl = capabilities.dynamic_lite;
  const ready = dl.enabled && dl.adb_available && dl.emulator_serial_configured;
  return {
    label: ready ? 'Runtime ready' : 'Runtime unavailable',
    ready,
    loading: false,
  };
}

const navItems: { id: AppPage; label: string; icon: typeof Home }[] = [
  { id: 'home',           label: 'Home',           icon: Home },
  { id: 'search',         label: 'Search',          icon: Search },
  { id: 'investigations', label: 'Investigations',  icon: FileText },
  { id: 'campaigns',      label: 'Campaigns',       icon: Dna },
];

export function TopNavigation({ page, onNavigate, capabilities }: TopNavigationProps) {
  const runtime = getRuntimeStatus(capabilities);

  return (
    <header className="topbar" role="banner">
      <div className="topbar-inner">
        <div className="brand">
          <span className="brand-shield" aria-hidden="true">
            <Shield size={17} strokeWidth={1.8} />
          </span>
          FraudShield
        </div>

        <nav className="nav" aria-label="Main navigation">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-btn${page === id ? ' active' : ''}`}
              onClick={() => onNavigate(id)}
              aria-current={page === id ? 'page' : undefined}
              type="button"
            >
              <Icon size={14} strokeWidth={1.8} />
              {label}
            </button>
          ))}
          <button className="nav-btn" type="button" aria-label="About">
            <Info size={14} strokeWidth={1.8} />
            About
          </button>
        </nav>

        <div className="nav-status">
          {!runtime.loading && (
            <>
              <span
                className={`live-dot${runtime.ready ? '' : ' offline'}`}
                aria-hidden="true"
              />
              <span>{runtime.label}</span>
            </>
          )}
          <div className="avatar" aria-label="Analyst">AN</div>
        </div>
      </div>
    </header>
  );
}
