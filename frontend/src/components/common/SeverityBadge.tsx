import React from 'react';
import type { SeverityLevel } from '../../types/api';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  className = '',
}) => {
  const norm = (severity || 'LOW').toUpperCase() as SeverityLevel;

  let badgeStyle = 'soc-badge-info';
  if (norm === 'CRITICAL') badgeStyle = 'soc-badge-critical';
  else if (norm === 'HIGH') badgeStyle = 'soc-badge-high';
  else if (norm === 'MEDIUM') badgeStyle = 'soc-badge-medium';
  else if (norm === 'LOW') badgeStyle = 'soc-badge-low';

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3 py-1.5 font-bold',
  };

  return (
    <span className={`soc-badge ${badgeStyle} ${sizeClasses[size]} ${className}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
      {norm}
    </span>
  );
};
