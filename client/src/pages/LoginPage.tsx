import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useCrypto } from '../contexts/CryptoContext';
import * as api from '../services/api';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login } = useAuth();
  const { restoreIdentityOnLogin, regenerateIdentity } = useCrypto();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const isVerifiedBanner = searchParams.get('verified') === 'true';

  const handleResend = async () => {
    if (!email) {
      setError('Please enter your email above to resend verification link');
      return;
    }
    setResendStatus('Resending verification email...');
    try {
      const res = await api.resendVerification(email.trim());
      setResendStatus(res.message || 'Verification email resent!');
    } catch (err: any) {
      setResendStatus(err.message || 'Failed to resend verification email');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResendStatus(null);

    if (!email.trim() || !password) {
      setError('Email and password are required');
      return;
    }

    setSubmitting(true);
    setStatus('Authenticating...');
    try {
      const user = await login(email.trim(), password);
      setStatus('Loading ML-DSA-65 identity from IndexedDB / encrypted backup...');
      const identity = await restoreIdentityOnLogin(user.id, password);
      if (!identity) {
        setStatus('Initializing post-quantum cryptographic identity and CA certificate...');
        await regenerateIdentity(password);
      }
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Invalid credentials');
    } finally {
      setSubmitting(false);
      setStatus(null);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-200 flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md bg-[#111827] border border-gray-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <Link to="/" className="inline-flex items-center gap-2">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#00ff41]/20 to-cyan-500/20 border border-[#00ff41]/40 flex items-center justify-center font-mono text-sm font-bold text-[#00ff41]">
              PQ
            </div>
          </Link>
          <h1 className="text-2xl font-bold text-white">Sign In</h1>
          <p className="text-xs text-gray-400">
            Unlock your local post-quantum cryptographic keystore
          </p>
        </div>

        {isVerifiedBanner && (
          <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 text-xs flex items-center gap-2">
            <span className="text-emerald-400 font-bold">✓</span>
            <span>Email verified successfully! You may now sign in.</span>
          </div>
        )}

        {error && (
          <div className="p-3 rounded-lg bg-red-950/60 border border-red-500/50 text-red-300 text-xs space-y-2">
            <div>{error}</div>
            {error.toLowerCase().includes('not verified') && (
              <button
                type="button"
                onClick={handleResend}
                className="text-xs text-cyan-400 hover:underline font-semibold block cursor-pointer"
              >
                Resend verification email
              </button>
            )}
          </div>
        )}

        {resendStatus && (
          <div className="p-3 rounded-lg bg-cyan-950/50 border border-cyan-500/40 text-cyan-300 text-xs">
            {resendStatus}
          </div>
        )}

        {status && (
          <div className="p-3 rounded-lg bg-cyan-950/50 border border-cyan-500/40 text-cyan-300 text-xs font-mono">
            {status}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1.5">
              Email Address
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="alice@example.com"
              className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-medium text-gray-300">
                Password
              </label>
              <Link
                to="/reset-password"
                className="text-xs text-cyan-400 hover:underline"
              >
                Forgot password?
              </Link>
            </div>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
          >
            {submitting ? 'Unlocking Keystore...' : 'Sign In & Unlock Keystore'}
          </button>
        </form>

        <p className="text-center text-xs text-gray-400">
          Don't have an account?{' '}
          <Link to="/register" className="text-cyan-400 hover:underline font-medium">
            Create PQ Identity
          </Link>
        </p>
      </div>
    </div>
  );
};
