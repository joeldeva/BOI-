import React from 'react';

interface SyntheticBadgeProps {
  label?: string;
  size?: 'sm' | 'md';
}

export const SyntheticBadge: React.FC<SyntheticBadgeProps> = ({
  label = 'SYNTHETIC DEMO DATA',
  size = 'md',
}) => {
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-bold tracking-wider rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 ${
        size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-2.5 py-1'
      }`}
      title="This demo sample was generated deterministically for demonstration and testing purposes."
    >
      <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
      {label}
    </span>
  );
};
