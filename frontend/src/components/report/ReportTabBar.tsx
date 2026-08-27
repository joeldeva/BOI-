import { Shield, Fingerprint, AlertTriangle, Smartphone, Code, Brain, Activity, Globe, Dna } from 'lucide-react';

export type ReportTab =
  | 'overview' | 'fingerprints' | 'intel' | 'apk'
  | 'code' | 'ai' | 'behavior' | 'network' | 'frauddna';

interface ReportTabBarProps {
  active: ReportTab;
  onChange: (tab: ReportTab) => void;
}

const TABS: { id: ReportTab; label: string; icon: typeof Shield }[] = [
  { id: 'overview',     label: 'Overview',         icon: Shield },
  { id: 'fingerprints', label: 'Fingerprints',      icon: Fingerprint },
  { id: 'intel',        label: 'Threat intel',      icon: AlertTriangle },
  { id: 'apk',          label: 'APK analysis',      icon: Smartphone },
  { id: 'code',         label: 'Code analysis',     icon: Code },
  { id: 'ai',           label: 'AI investigation',  icon: Brain },
  { id: 'behavior',     label: 'Behavior analysis', icon: Activity },
  { id: 'network',      label: 'Network analysis',  icon: Globe },
  { id: 'frauddna',     label: 'FraudDNA',          icon: Dna },
];

export function ReportTabBar({ active, onChange }: ReportTabBarProps) {
  return (
    <div className="report-tabs-wrap" role="tablist" aria-label="Investigation report sections">
      <div className="report-tabs">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`report-tab${active === id ? ' active' : ''}`}
            onClick={() => onChange(id)}
            role="tab"
            aria-selected={active === id}
            id={`tab-${id}`}
            aria-controls={`tabpanel-${id}`}
            type="button"
          >
            <Icon size={14} strokeWidth={1.8} />
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
