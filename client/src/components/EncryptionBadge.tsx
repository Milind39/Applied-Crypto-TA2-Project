import React from 'react';
import { HandshakeStatus } from '../types';

interface EncryptionBadgeProps {
  status?: HandshakeStatus;
  onInitiateHandshake?: () => void;
  compact?: boolean;
}

export const EncryptionBadge: React.FC<EncryptionBadgeProps> = ({
  status,
  onInitiateHandshake,
  compact = false,
}) => {
  const state = status?.state || 'idle';

  if (state === 'established') {
    return (
      <div
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/60 border border-[#00ff41]/40 text-[#00ff41] text-xs font-medium glow-green"
        title="End-to-End Encrypted with ML-KEM-768 + ML-DSA-65 + AES-256-GCM"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
          />
        </svg>
        {!compact && <span>PQ E2EE Active</span>}
      </div>
    );
  }

  if (state === 'initiating' || state === 'responding') {
    return (
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 text-xs font-medium">
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
        {!compact && (
          <span>{state === 'initiating' ? 'ML-KEM Handshake...' : 'Verifying Peer...'}</span>
        )}
      </div>
    );
  }

  if (state === 'failed') {
    return (
      <button
        type="button"
        onClick={onInitiateHandshake}
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-950/60 border border-red-500/50 text-red-400 text-xs font-medium hover:bg-red-900/50 transition cursor-pointer"
        title={status?.error || 'Handshake failed — click to retry'}
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01M5.07 19h13.86c1.54 0 2.5-1.67 1.73-3L13.73 4c-.77-1.33-2.69-1.33-3.46 0L3.34 16c-.77 1.33.19 3 1.73 3z"
          />
        </svg>
        {!compact && <span>Handshake Failed (Retry)</span>}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={onInitiateHandshake}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-950/50 border border-amber-500/40 text-amber-300 text-xs font-medium hover:bg-amber-900/40 transition cursor-pointer"
      title="Click to establish ML-KEM-768 + ML-DSA-65 session keys"
    >
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"
        />
      </svg>
      {!compact && <span>Establish PQ Session</span>}
    </button>
  );
};
