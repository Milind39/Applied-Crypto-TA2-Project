import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useSocket } from '../contexts/SocketContext';
import { useCrypto } from '../contexts/CryptoContext';

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, logout } = useAuth();
  const { connected } = useSocket();
  const { cryptoReady, cryptoIdentity } = useCrypto();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0a0a0f] text-gray-200">
      <header className="h-14 border-b border-gray-800 bg-[#111827]/90 backdrop-blur px-4 sm:px-6 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-6">
          <Link to="/dashboard" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#00ff41]/20 to-cyan-500/20 border border-[#00ff41]/40 flex items-center justify-center font-mono text-xs font-bold text-[#00ff41]">
              PQ
            </div>
            <span className="font-semibold text-sm sm:text-base tracking-tight text-gray-100">
              PQ Messenger
            </span>
          </Link>

          <nav className="flex items-center gap-1">
            <Link
              to="/dashboard"
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition ${
                location.pathname === '/dashboard'
                  ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
              }`}
            >
              Messages
            </Link>
            <Link
              to="/security"
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition ${
                location.pathname === '/security'
                  ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
              }`}
            >
              Security & Keys
            </Link>
          </nav>
        </div>

        <div className="flex items-center gap-3 sm:gap-4">
          <div className="hidden md:flex items-center gap-2 text-xs font-mono">
            <span
              className={`px-2 py-0.5 rounded border ${
                cryptoReady
                  ? 'border-[#00ff41]/30 bg-emerald-950/40 text-[#00ff41]'
                  : 'border-amber-500/30 bg-amber-950/40 text-amber-300'
              }`}
            >
              {cryptoReady ? 'WASM: READY' : 'WASM: LOADING'}
            </span>
            <span
              className={`px-2 py-0.5 rounded border ${
                connected
                  ? 'border-cyan-500/30 bg-cyan-950/40 text-cyan-400'
                  : 'border-red-500/30 bg-red-950/40 text-red-400'
              }`}
            >
              {connected ? 'SOCKET: LIVE' : 'SOCKET: OFFLINE'}
            </span>
            {cryptoIdentity && (
              <span
                className="px-2 py-0.5 rounded border border-gray-700 bg-gray-900 text-gray-400"
                title={cryptoIdentity.certificate.fingerprint}
              >
                FP: {cryptoIdentity.certificate.fingerprint.slice(0, 8)}...
              </span>
            )}
          </div>

          {user && (
            <div className="flex items-center gap-2 sm:gap-3">
              <span className="text-xs sm:text-sm font-medium text-gray-300">
                @{user.username}
              </span>
              {user.isEmailVerified ? (
                <span className="text-[10px] text-emerald-400 font-mono hidden sm:inline" title="Email Verified">
                  ✓ Verified
                </span>
              ) : (
                <span className="text-[10px] text-amber-400 font-mono hidden sm:inline" title="Email Not Verified">
                  Pending Verify
                </span>
              )}
              <button
                type="button"
                onClick={handleLogout}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-800 hover:bg-red-950/70 hover:text-red-300 border border-gray-700 hover:border-red-500/40 text-gray-300 transition cursor-pointer"
              >
                Logout
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="flex-1 flex flex-col min-h-0">{children}</main>
    </div>
  );
};
