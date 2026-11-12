import React, { useEffect, useState } from 'react';
import { Layout } from '../components/Layout';
import { CertificateViewer } from '../components/CertificateViewer';
import { useAuth } from '../contexts/AuthContext';
import { useCrypto } from '../contexts/CryptoContext';
import { verifyPeerCertificate } from '../crypto/handshake';
import * as api from '../services/api';

export const SecurityPage: React.FC = () => {
  const { user } = useAuth();
  const {
    cryptoReady,
    cryptoIdentity,
    caPublicKey,
    crl,
    sessionKeys,
    revokeOwnCertificate,
    regenerateIdentity,
    refreshCAInfo,
  } = useCrypto();

  const [verifiedLocally, setVerifiedLocally] = useState<boolean | null>(null);
  const [verificationReason, setVerificationReason] = useState<string | undefined>();
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showRotateModal, setShowRotateModal] = useState(false);
  const [backupPassword, setBackupPassword] = useState('');

  useEffect(() => {
    if (!cryptoIdentity || !caPublicKey || !cryptoReady) {
      setVerifiedLocally(null);
      return;
    }

    verifyPeerCertificate(
      cryptoIdentity.certificate,
      caPublicKey,
      crl,
      user?.id
    ).then((res) => {
      setVerifiedLocally(res.valid);
      setVerificationReason(res.reason);
    });
  }, [cryptoIdentity, caPublicKey, crl, cryptoReady, user?.id]);

  const handleRevoke = async () => {
    setActionMsg(null);
    setActionError(null);
    setBusy(true);
    try {
      await revokeOwnCertificate();
      setActionMsg('Certificate revoked and added to CA CRL.');
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleRegenerate = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setActionMsg(null);
    setActionError(null);
    setBusy(true);
    try {
      const pw = backupPassword.trim() ? backupPassword : undefined;
      await regenerateIdentity(pw);
      setActionMsg(
        pw
          ? 'Generated new ML-DSA-65 key pair in IndexedDB, issued fresh CA certificate, and updated encrypted key backup.'
          : 'Generated new ML-DSA-65 key pair in IndexedDB and issued a fresh CA certificate (server backup not updated).'
      );
      setBackupPassword('');
      setShowRotateModal(false);
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleServerVerify = async () => {
    if (!cryptoIdentity?.certificate.rawCertificate) return;
    setActionMsg(null);
    setActionError(null);
    try {
      const res = await api.verifyCertificate(
        cryptoIdentity.certificate.rawCertificate,
        cryptoIdentity.certificate.caSignature
      );
      setActionMsg(
        `CA Verification Endpoint: valid=${res.valid}, signatureValid=${res.signatureValid}, revoked=${res.revoked}, expired=${res.expired}`
      );
    } catch (err) {
      setActionError((err as Error).message);
    }
  };

  const activeSessions = Array.from(sessionKeys.values());

  return (
    <Layout>
      <div className="flex-1 overflow-y-auto p-4 sm:p-8">
        <div className="max-w-5xl mx-auto space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold text-white">
                Security, Keys & Certificates
              </h1>
              <p className="text-sm text-gray-400">
                Inspect your local ML-DSA-65 identity, CA verification status, and active ML-KEM-768 sessions.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={refreshCAInfo}
                className="px-3.5 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-xs font-medium text-gray-200 transition cursor-pointer"
              >
                Refresh CA & CRL
              </button>
              <button
                type="button"
                onClick={() => {
                  setActionMsg(null);
                  setActionError(null);
                  setShowRotateModal(true);
                }}
                disabled={busy}
                className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-xs font-semibold text-white transition cursor-pointer"
              >
                {cryptoIdentity ? 'Rotate ML-DSA-65 Keys' : 'Generate ML-DSA-65 Keys'}
              </button>
            </div>
          </div>

          {showRotateModal && (
            <form
              onSubmit={handleRegenerate}
              className="bg-[#111827] border border-cyan-500/40 rounded-xl p-5 space-y-4"
            >
              <div>
                <h2 className="text-sm font-semibold text-white">
                  {cryptoIdentity
                    ? 'Rotate ML-DSA-65 Identity & Update Encrypted Backup'
                    : 'Generate ML-DSA-65 Identity'}
                </h2>
                <p className="text-xs text-gray-400 mt-1">
                  Optionally enter your account password to encrypt the new private signing key with PBKDF2 + AES-256-GCM and sync it to{' '}
                  <span className="font-mono text-gray-300">/api/keys/backup</span>.
                </p>
              </div>
              <input
                type="password"
                value={backupPassword}
                onChange={(e) => setBackupPassword(e.target.value)}
                placeholder="Account password (optional for encrypted backup)"
                className="w-full bg-[#0a0a0f] border border-gray-800 rounded-lg px-3.5 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
              />
              <div className="flex flex-wrap justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setBackupPassword('');
                    setShowRotateModal(false);
                  }}
                  disabled={busy}
                  className="px-3.5 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs font-medium text-gray-300 transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-xs font-semibold text-white transition cursor-pointer"
                >
                  {busy
                    ? 'Generating & Certifying...'
                    : backupPassword.trim()
                      ? 'Confirm Rotation + Encrypted Backup'
                      : 'Confirm Rotation (Local Only)'}
                </button>
              </div>
            </form>
          )}

          {actionMsg && (
            <div className="p-3 rounded-xl bg-emerald-950/50 border border-[#00ff41]/40 text-xs text-[#00ff41] font-mono">
              {actionMsg}
            </div>
          )}
          {actionError && (
            <div className="p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-xs text-red-300">
              {actionError}
            </div>
          )}

          {/* Certificate Details */}
          {cryptoIdentity ? (
            <div className="space-y-3">
              <CertificateViewer
                certificate={cryptoIdentity.certificate}
                verifiedLocally={verifiedLocally}
                verificationReason={verificationReason}
              />
              <div className="flex flex-wrap items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={handleServerVerify}
                  className="px-4 py-2 rounded-lg bg-[#111827] hover:bg-gray-800 border border-gray-700 text-xs font-medium text-cyan-400 transition cursor-pointer"
                >
                  Verify Against CA Endpoint
                </button>
                <button
                  type="button"
                  onClick={handleRevoke}
                  disabled={busy || cryptoIdentity.certificate.isRevoked}
                  className="px-4 py-2 rounded-lg bg-red-950/60 hover:bg-red-900/70 disabled:opacity-40 border border-red-500/50 text-xs font-semibold text-red-300 transition cursor-pointer"
                >
                  {cryptoIdentity.certificate.isRevoked
                    ? 'Certificate Revoked'
                    : 'Revoke Certificate'}
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-[#111827] border border-amber-500/40 rounded-xl p-6 text-sm text-amber-200">
              No local ML-DSA-65 signing key pair found in IndexedDB. Click{' '}
              <span className="font-semibold text-white">Generate ML-DSA-65 Keys</span>{' '}
              above to create a new local key pair and request a CA-signed certificate.
            </div>
          )}

          {/* Active Encrypted Sessions */}
          <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h2 className="text-sm font-semibold text-gray-100 uppercase tracking-wider">
                Active PQ Encrypted Sessions ({activeSessions.length})
              </h2>
              <span className="text-xs font-mono text-gray-400">
                ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM
              </span>
            </div>

            {activeSessions.length === 0 ? (
              <p className="text-xs text-gray-500">
                No active in-memory session keys. Open a chat in Messages and click
                "Establish PQ Session".
              </p>
            ) : (
              <div className="space-y-2.5">
                {activeSessions.map((s) => (
                  <div
                    key={s.conversationId}
                    className="bg-[#0a0a0f] border border-gray-800 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="font-mono text-cyan-400">
                        Conversation: {s.conversationId}
                      </div>
                      <div className="font-mono text-gray-400">
                        Peer Fingerprint: {s.peerFingerprint?.slice(0, 24)}...
                      </div>
                    </div>
                    <div className="flex items-center gap-3 font-mono">
                      <span className="text-gray-400">
                        Seq: {s.sequenceNumber}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-[#00ff41]/40 text-[#00ff41]">
                        {s.peerVerified ? 'CA VERIFIED' : 'ESTABLISHED'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* CA & CRL Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 space-y-2">
              <h3 className="text-sm font-semibold text-gray-100 uppercase tracking-wider">
                Certificate Authority Public Key
              </h3>
              <p className="text-xs text-gray-400">
                Used locally to verify peer ML-DSA-65 certificates before trusting KEM keys.
              </p>
              <div className="bg-[#0a0a0f] border border-gray-800 rounded-lg p-3 font-mono text-[11px] text-gray-400 break-all max-h-28 overflow-y-auto">
                {caPublicKey || 'Unavailable'}
              </div>
            </div>

            <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 space-y-2">
              <h3 className="text-sm font-semibold text-gray-100 uppercase tracking-wider">
                Certificate Revocation List (CRL)
              </h3>
              <p className="text-xs text-gray-400">
                Revoked fingerprints ({crl.length}) are rejected during handshake verification.
              </p>
              <div className="bg-[#0a0a0f] border border-gray-800 rounded-lg p-3 font-mono text-[11px] text-gray-400 max-h-28 overflow-y-auto space-y-1">
                {crl.length === 0 ? (
                  <span className="text-gray-500">CRL is empty</span>
                ) : (
                  crl.map((fp) => (
                    <div key={fp} className="text-red-400 break-all">
                      {fp}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};
