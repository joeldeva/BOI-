import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface HashValueProps {
  value: string;
  truncate?: boolean;
  id?: string;
}

export function HashValue({ value, truncate = false, id }: HashValueProps) {
  const [copied, setCopied] = useState(false);
  const display = truncate && value.length > 26
    ? `${value.slice(0, 10)}…${value.slice(-8)}`
    : value;

  const copy = () => {
    void navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span id={id} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <code className="hash" title={value}>{display}</code>
      <button className="copy-btn" onClick={copy} aria-label="Copy to clipboard" type="button">
        {copied ? <Check size={13} /> : <Copy size={13} />}
      </button>
    </span>
  );
}
