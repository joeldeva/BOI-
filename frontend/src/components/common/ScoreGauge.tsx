import React from 'react';

interface ScoreGaugeProps {
  score: number;
  maxScore?: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
  sublabel?: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score = 0,
  maxScore = 100,
  size = 120,
  strokeWidth = 10,
  label = 'RISK SCORE',
  sublabel,
}) => {
  const normScore = Math.min(Math.max(score, 0), maxScore);
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normScore / maxScore) * circumference;

  let color = '#10b981'; // Low green
  if (normScore >= 75) color = '#ef4444'; // Critical red
  else if (normScore >= 50) color = '#f97316'; // High orange
  else if (normScore >= 25) color = '#f59e0b'; // Medium yellow

  return (
    <div className="relative inline-flex flex-col items-center justify-center">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="font-display font-extrabold text-2xl tracking-tight text-white">
          {Math.round(normScore)}
        </span>
        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
          {label}
        </span>
        {sublabel && (
          <span className="text-[9px] text-slate-500 max-w-[80px] truncate">
            {sublabel}
          </span>
        )}
      </div>
    </div>
  );
};
