import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useCrypto } from '../contexts/CryptoContext';

const FEATURES = [
  {
    title: 'End-to-End Encryption',
    desc: 'Every message is encrypted inside your browser with AES-256-GCM and a fresh 96-bit CSPRNG nonce before leaving your device.',
    badge: 'AES-256-GCM',
  },
  {
    title: 'Post-Quantum Key Exchange',
    desc: 'Mutually authenticated ML-KEM-768 key encapsulation prevents harvest-now-decrypt-later attacks by future quantum computers.',
    badge: 'ML-KEM-768',
  },
  {
    title: 'Zero-Knowledge Server',
    desc: 'Private keys never leave IndexedDB unencrypted. The server relays and stores only ciphertext, nonces, tags, and AAD.',
    badge: 'ZERO-KNOWLEDGE',
  },
  {
    title: 'Certificate-Based Auth',
    desc: 'Every identity is bound to a CA-signed ML-DSA-65 certificate verified locally against the CA public key and CRL.',
    badge: 'ML-DSA-65',
  },
];

const ALGORITHMS = [
  {
    name: 'ML-DSA-65',
    standard: 'NIST FIPS 204',
    role: 'Digital Signatures & CA Certificates',
    strength: '192-bit Post-Quantum (Level 3)',
  },
  {
    name: 'ML-KEM-768',
    standard: 'NIST FIPS 203',
    role: 'Ephemeral Authenticated Key Exchange',
    strength: '192-bit Post-Quantum (Level 3)',
  },
  {
    name: 'HKDF-SHA-256',
    standard: 'RFC 5869',
    role: 'Transcript-Bound Directional Key Derivation',
    strength: '256-bit Key Derivation',
  },
  {
    name: 'AES-256-GCM',
    standard: 'NIST SP 800-38D',
    role: 'Authenticated Message Encryption + AAD',
    strength: '256-bit Symmetric AEAD',
  },
];

export const LandingPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const { cryptoReady } = useCrypto();

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-200 flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-gray-800/80 bg-[#0a0a0f]/90 backdrop-blur sticky top-0 z-20">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#00ff41]/20 to-cyan-500/20 border border-[#00ff41]/40 flex items-center justify-center font-mono text-sm font-bold text-[#00ff41]">
              PQ
            </div>
            <div>
              <span className="font-bold text-gray-100 tracking-tight">
                PQ Messenger
              </span>
              <span className="hidden sm:inline-block ml-2 text-[11px] font-mono text-[#00ff41] bg-emerald-950/60 border border-[#00ff41]/30 px-2 py-0.5 rounded-full">
                {cryptoReady ? 'WASM CRYPTO READY' : 'INITIALIZING WASM...'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <Link
                to="/dashboard"
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition"
              >
                Open Dashboard
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="px-4 py-2 rounded-lg border border-gray-700 hover:border-cyan-500/60 text-gray-300 hover:text-white text-sm font-medium transition"
                >
                  Login
                </Link>
                <Link
                  to="/register"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition shadow-[0_0_20px_rgba(6,182,212,0.25)]"
                >
                  Register
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden py-16 sm:py-24 px-4 sm:px-6">
        <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_top,rgba(6,182,212,0.12),transparent_55%)]" />
        <div className="max-w-5xl mx-auto text-center relative z-10 space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#111827] border border-gray-800 text-xs font-mono text-[#00ff41]">
            <span className="w-2 h-2 rounded-full bg-[#00ff41] animate-pulse" />
            NIST FIPS 203 + FIPS 204 Client-Side WebAssembly Cryptography
          </div>

          <h1 className="text-4xl sm:text-6xl font-bold tracking-tight text-white leading-tight">
            Post-Quantum{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#00ff41] to-cyan-400">
              Secure Messenger
            </span>
          </h1>

          <p className="max-w-2xl mx-auto text-base sm:text-lg text-gray-400 leading-relaxed">
            Quantum-resistant end-to-end encrypted messaging running entirely in your
            browser. Ephemeral ML-KEM-768 handshakes authenticated by CA-signed
            ML-DSA-65 certificates, with zero plaintext ever reaching the server.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <Link
              to="/register"
              className="px-7 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-semibold text-sm sm:text-base transition shadow-[0_0_25px_rgba(0,255,65,0.2)]"
            >
              Generate Quantum Identity
            </Link>
            <Link
              to="/login"
              className="px-7 py-3 rounded-xl bg-[#111827] hover:bg-gray-800 border border-gray-700 text-gray-200 font-semibold text-sm sm:text-base transition"
            >
              Sign In to Existing Account
            </Link>
          </div>
        </div>
      </section>

      {/* Feature Cards */}
      <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-16 w-full">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="bg-[#111827] border border-gray-800 hover:border-cyan-500/40 rounded-2xl p-6 transition space-y-3"
            >
              <span className="inline-block px-2.5 py-1 rounded-md bg-cyan-950/60 border border-cyan-500/30 text-[11px] font-mono text-cyan-400">
                {f.badge}
              </span>
              <h3 className="text-base font-semibold text-gray-100">{f.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Cryptographic Suite Overview */}
      <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-20 w-full">
        <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-6">
            <div>
              <h2 className="text-xl font-bold text-white">
                Cryptographic Architecture
              </h2>
              <p className="text-sm text-gray-400">
                All key generation, signing, verification, and encryption run client-side via WebAssembly & Web Crypto API.
              </p>
            </div>
            <span className="text-xs font-mono text-[#00ff41]">
              PRIVATE KEYS NEVER LEAVE BROWSER
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {ALGORITHMS.map((algo) => (
              <div
                key={algo.name}
                className="bg-[#0a0a0f] border border-gray-800 rounded-xl p-4 flex items-start justify-between gap-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-cyan-400">
                      {algo.name}
                    </span>
                    <span className="text-[11px] font-mono text-gray-500">
                      ({algo.standard})
                    </span>
                  </div>
                  <p className="text-sm text-gray-300 mt-1">{algo.role}</p>
                </div>
                <span className="text-[11px] font-mono text-[#00ff41] bg-emerald-950/50 border border-[#00ff41]/30 px-2 py-1 rounded flex-shrink-0">
                  {algo.strength}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="mt-auto border-t border-gray-800/80 py-6 px-4 text-center text-xs text-gray-500 font-mono">
        PQ Messenger — Post-Quantum End-to-End Encrypted Communication Platform
      </footer>
    </div>
  );
};
