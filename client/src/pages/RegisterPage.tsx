import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useCrypto } from '../contexts/CryptoContext';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const { register } = useAuth();
  const { initializeIdentityForRegistration } = useCrypto();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [cryptoStep, setCryptoStep] = useState<string | null>(null);
  const [registeredEmail, setRegisteredEmail] = useState<string | null>(null);

  const validate = (): string | null => {
    const trimmedUser = username.trim();
    if (trimmedUser.length < 3 || trimmedUser.length > 50) {
      return 'Username must be between 3 and 50 characters';
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return 'Please enter a valid email address';
    }
    if (password.length < 8) {
      return 'Password must be at least 8 characters long';
    }
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password)) {
      return 'Password must contain uppercase, lowercase, and at least one digit';
    }
    if (password !== confirmPassword) {
      return 'Passwords do not match';
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);
    setCryptoStep('Registering account...');
    try {
      const res = await register(
        username.trim(),
        email.trim(),
        password,
        confirmPassword
      );

      // If email verification is required or not verified, user must verify before login
      if (res.needsVerification || !res.token || !res.user?.isEmailVerified) {
        setRegisteredEmail(email.trim());
        return;
      }

      // If already verified or in test mode with token
      await initializeIdentityForRegistration(res.user.id, password, (step) => {
        setCryptoStep(step);
      });
      navigate('/dashboard');
    } catch (err) {
      setError((err as Error).message || 'Registration failed');
    } finally {
      setSubmitting(false);
      setCryptoStep(null);
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
          <h1 className="text-2xl font-bold text-white">
            {registeredEmail ? 'Verify Your Email' : 'Create PQ Identity'}
          </h1>
          <p className="text-xs text-gray-400">
            {registeredEmail
              ? 'Complete email verification before signing in'
              : 'Generates an ML-DSA-65 signing key pair locally and requests a CA certificate'}
          </p>
        </div>

        {registeredEmail ? (
          <div className="space-y-6">
            <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/40 text-sm space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold">
                <span className="text-lg">✉️</span>
                <span>Verification Link Sent</span>
              </div>
              <p className="text-gray-300 text-xs leading-relaxed">
                We sent a verification email to <strong className="text-white font-mono">{registeredEmail}</strong>.
              </p>
              <p className="text-gray-400 text-xs leading-relaxed">
                Please check your inbox (and spam folder) and click the link to verify your email address. You will not be able to log in until your email is verified.
              </p>
            </div>

            <Link
              to="/login"
              className="block w-full text-center py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition"
            >
              Go to Sign In
            </Link>
          </div>
        ) : (
          <>
            {error && (
              <div className="p-3 rounded-lg bg-red-950/60 border border-red-500/50 text-red-300 text-xs">
                {error}
              </div>
            )}

            {cryptoStep && (
              <div className="p-3 rounded-lg bg-emerald-950/50 border border-[#00ff41]/40 text-[#00ff41] text-xs font-mono flex items-center gap-2.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#00ff41] animate-ping flex-shrink-0" />
                <span>{cryptoStep}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1.5">
                  Username
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="alice"
                  className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

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
                <label className="block text-xs font-medium text-gray-300 mb-1.5">
                  Password
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 8 chars, upper/lower/digit"
                  className="w-full bg-[#0a0a0f] border border-gray-800 rounded-xl px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1.5">
                  Confirm Password
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
                disabled={submitting}
                className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
              >
                {submitting
                  ? 'Creating Account...'
                  : 'Register Account'}
              </button>
            </form>

            <p className="text-center text-xs text-gray-400">
              Already have an account?{' '}
              <Link to="/login" className="text-cyan-400 hover:underline font-medium">
                Sign in
              </Link>
            </p>
          </>
        )}
      </div>
    </div>
  );
};
