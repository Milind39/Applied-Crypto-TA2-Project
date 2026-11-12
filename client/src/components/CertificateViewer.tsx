import React from 'react';
import { Certificate } from '../types';

interface CertificateViewerProps {
  certificate: Certificate;
  verifiedLocally?: boolean | null;
  verificationReason?: string;
}

export const CertificateViewer: React.FC<CertificateViewerProps> = ({
  certificate,
  verifiedLocally,
  verificationReason,
}) => {
  const isExpired = new Date(certificate.expiresAt) < new Date();
  const statusLabel = certificate.isRevoked
    ? 'REVOKED'
    : isExpired
      ? 'EXPIRED'
      : verifiedLocally === false
        ? 'INVALID SIGNATURE'
        : 'ACTIVE & CA-SIGNED';

  const statusColor =
    certificate.isRevoked || isExpired || verifiedLocally === false
      ? 'text-red-400 bg-red-950/50 border-red-500/40'
      : 'text-[#00ff41] bg-emerald-950/50 border-[#00ff41]/40';

  return (
    <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-100 uppercase tracking-wider">
            X.509-Style Post-Quantum Certificate
          </h3>
          <p className="text-xs text-gray-400">
            Algorithm: NIST FIPS 204 ML-DSA-65 (Dilithium3)
          </p>
        </div>
        <span
          className={`px-3 py-1 rounded-full text-xs font-mono font-semibold border ${statusColor}`}
        >
          {statusLabel}
        </span>
      </div>

      {verificationReason && verifiedLocally === false && (
        <div className="text-xs text-red-400 bg-red-950/40 border border-red-800/60 rounded-lg px-3 py-2">
          Verification Error: {verificationReason}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
        <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
          <div className="text-xs text-gray-400 mb-1">Subject Username</div>
          <div className="font-mono text-cyan-400">{certificate.username || 'N/A'}</div>
        </div>
        <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
          <div className="text-xs text-gray-400 mb-1">Subject User ID</div>
          <div className="font-mono text-xs text-gray-300 break-all">
            {certificate.userId}
          </div>
        </div>
        <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
          <div className="text-xs text-gray-400 mb-1">Issued At</div>
          <div className="font-mono text-xs text-gray-200">
            {certificate.issuedAt
              ? new Date(certificate.issuedAt).toLocaleString()
              : 'N/A'}
          </div>
        </div>
        <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
          <div className="text-xs text-gray-400 mb-1">Expires At</div>
          <div className="font-mono text-xs text-gray-200">
            {certificate.expiresAt
              ? new Date(certificate.expiresAt).toLocaleString()
              : 'N/A'}
          </div>
        </div>
      </div>

      <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
        <div className="text-xs text-gray-400 mb-1">
          SHA-256 Public Key Fingerprint
        </div>
        <div className="font-mono text-xs text-[#00ff41] break-all select-all">
          {certificate.fingerprint}
        </div>
      </div>

      <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
        <div className="text-xs text-gray-400 mb-1">
          ML-DSA-65 Public Signing Key (Base64)
        </div>
        <div className="font-mono text-[11px] text-gray-400 break-all max-h-20 overflow-y-auto">
          {certificate.publicSigningKey}
        </div>
      </div>

      <div className="bg-[#0a0a0f] border border-gray-800/80 rounded-lg p-3">
        <div className="text-xs text-gray-400 mb-1">
          CA ML-DSA-65 Signature (Base64)
        </div>
        <div className="font-mono text-[11px] text-gray-400 break-all max-h-20 overflow-y-auto">
          {certificate.caSignature}
        </div>
      </div>
    </div>
  );
};
