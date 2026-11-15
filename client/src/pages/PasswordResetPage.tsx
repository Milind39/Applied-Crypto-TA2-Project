import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import * as api from '../services/api';

export const PasswordResetPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const queryToken = searchParams.get('token') || '';
  const queryEmail = searchParams.get('email') || '';

  const [step, setStep] = useState<'request' | 'confirm' | 'done'>(() =>
    queryToken ? 'confirm' : 'request'
  );
  const [email, setEmail] = useState(() => queryEmail);
  const [token, setToken] = useState(() => queryToken);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [info, setInfo] = useState<string | null>(() =>
    queryToken ? 'Reset token loaded from email link. Please set your new password below.' : null
  );
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (queryToken) {
      setToken(queryToken);
      setStep('confirm');
      setInfo('Reset token loaded from email link. Please set your new password below.');
    }
    if (queryEmail) {
      setEmail(queryEmail);
    }
  }, [queryToken, queryEmail]);

  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setLoading(true);
    try {
      const res = await api.requestPasswordReset(email.trim());
      setInfo(
        res.message ||
          'If an account with that email exists, a password reset token has been sent to your email. Check your inbox to enter the token, or click the direct link in the email.'
      );
      setStep('confirm');
    } catch (err) {
      setError((err as Error).message || 'Failed to request password reset');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!token.trim()) {
      setError('Please provide the reset token sent to your email');
      return;
    }

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
      setError('Password must contain uppercase, lowercase, and at least one digit');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      const res = await api.confirmPasswordReset(
        token.trim(),
        newPassword,
        confirmPassword
      );
      setInfo(res.message);
      setStep('done');
    } catch (err) {
      setError((err as Error).message || 'Failed to confirm password reset');
    } finally {
      setLoading(false);
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
          <h1 className="text-2xl font-bold text-white">Account Recovery</h1>
          <p className="text-xs text-gray-400">
            Reset your account password. A secure token will be sent to your email to verify ownership.
          </p>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/60 border border-red-500/50 text-red-300 text-xs">
            {error}
          </div>
        )}
        {info && (
          <div className="p-3 rounded-lg bg-emerald-950/50 border border-[#00ff41]/40 text-[#00ff41] text-xs">
            {info}
          </div>
        )}

        {step === 'request' && (
          <form onSubmit={handleRequest} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Account Email
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
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
            >
              {loading ? 'Sending email...' : 'Send Reset Link & Token'}
            </button>
          </form>
        )}

        {step === 'confirm' && (
          <form onSubmit={handleConfirm} className="space-y-4">
            {email && (
              <div className="p-2.5 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-400">
                Account: <span className="text-cyan-400 font-mono">{email}</span>
              </div>
            )}
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Reset Token
              </label>
              <input
                type="text"
                required
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste the reset token from your email"
                className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm font-mono text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
              />
              <p className="text-[11px] text-gray-500 mt-1">
                Enter the token from the email sent to you, or click the link directly from the email.
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                New Password
              </label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Min 8 chars, upper/lower/digit"
                className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Confirm New Password
              </label>
              <input
                type="password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat password"
                className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
            >
              {loading ? 'Updating Password...' : 'Reset Password'}
            </button>
            <div className="text-center pt-2">
              <button
                type="button"
                onClick={() => {
                  setStep('request');
                  setError(null);
                  setInfo(null);
                }}
                className="text-xs text-gray-400 hover:text-cyan-400 transition"
              >
                Didn't get an email? Request another token
              </button>
            </div>
          </form>
        )}

        {step === 'done' && (
          <div className="text-center space-y-4">
            <div className="p-4 rounded-xl bg-emerald-950/40 border border-[#00ff41]/40 text-sm space-y-2">
              <div className="text-[#00ff41] font-semibold text-base">✓ Password Changed</div>
              <p className="text-xs text-gray-300">
                Your password has been successfully updated. All active sessions have been terminated. You can now sign in with your new password.
              </p>
            </div>
            <Link
              to="/login"
              className="inline-block w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition"
            >
              Sign In Now
            </Link>
          </div>
        )}

        <p className="text-center text-xs text-gray-400">
          <Link to="/login" className="text-cyan-400 hover:underline">
            Back to Sign In
          </Link>
        </p>
      </div>
    </div>
  );
};
