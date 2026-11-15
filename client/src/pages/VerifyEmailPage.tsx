import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import * as api from '../services/api';

export const VerifyEmailPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const emailParam = searchParams.get('email') || '';

  const [loading, setLoading] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resending, setResending] = useState(false);
  const [resendStatus, setResendStatus] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setError('No verification token provided');
      setLoading(false);
      return;
    }

    let isMounted = true;
    (async () => {
      try {
        await api.verifyEmail(token);
        if (isMounted) {
          setSuccess(true);
          setError(null);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Verification failed');
          setSuccess(false);
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    })();

    return () => {
      isMounted = false;
    };
  }, [token]);

  const handleResend = async () => {
    if (!emailParam) {
      setError('Please provide your email to resend the verification link');
      return;
    }
    setResending(true);
    setResendStatus('Resending verification email...');
    try {
      const res = await api.resendVerification(emailParam);
      setResendStatus(res.message || 'Verification email resent!');
    } catch (err: any) {
      setResendStatus(err.message || 'Failed to resend verification email');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-200 flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md bg-[#111827] border border-gray-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6 text-center">
        <Link to="/" className="inline-flex items-center gap-2">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#00ff41]/20 to-cyan-500/20 border border-[#00ff41]/40 flex items-center justify-center font-mono text-sm font-bold text-[#00ff41]">
            PQ
          </div>
        </Link>
        <h1 className="text-2xl font-bold text-white">Email Verification</h1>

        {loading && (
          <div className="py-8 space-y-4">
            <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-sm text-gray-400">Verifying your email token...</p>
          </div>
        )}

        {!loading && success && (
          <div className="space-y-4 py-4">
            <div className="w-12 h-12 bg-emerald-500/20 border border-emerald-500/40 rounded-full flex items-center justify-center mx-auto text-emerald-400 text-xl font-bold">
              ✓
            </div>
            <h2 className="text-lg font-semibold text-white">Email Verified!</h2>
            <p className="text-xs text-gray-400">
              Your email has been successfully verified. You can now log in and access your post-quantum secure messaging dashboard.
            </p>
            <div className="pt-2">
              <Link
                to="/login"
                className="inline-block w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition"
              >
                Go to Sign In
              </Link>
            </div>
          </div>
        )}

        {!loading && error && (
          <div className="space-y-4 py-4">
            <div className="w-12 h-12 bg-red-500/20 border border-red-500/40 rounded-full flex items-center justify-center mx-auto text-red-400 text-xl font-bold">
              ✕
            </div>
            <h2 className="text-lg font-semibold text-white">Verification Failed</h2>
            <p className="text-xs text-red-300 bg-red-950/40 border border-red-500/30 rounded-lg p-3">
              {error}
            </p>
            {emailParam && (
              <button
                type="button"
                disabled={resending}
                onClick={handleResend}
                className="w-full py-2.5 rounded-xl bg-gray-800 hover:bg-gray-700 text-cyan-300 font-semibold text-sm transition disabled:opacity-50 cursor-pointer"
              >
                {resending ? 'Sending...' : 'Resend Verification Email'}
              </button>
            )}
            {resendStatus && (
              <p className="text-xs text-cyan-400">{resendStatus}</p>
            )}
            <div className="pt-2">
              <Link
                to="/login"
                className="text-xs text-gray-400 hover:text-gray-200 underline"
              >
                Back to Sign In
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
