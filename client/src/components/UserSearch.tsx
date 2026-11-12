import React, { useEffect, useState } from 'react';
import { User } from '../types';
import * as api from '../services/api';
import { OnlineIndicator } from './OnlineIndicator';

interface UserSearchProps {
  onSelectUser: (user: User) => Promise<void> | void;
}

export const UserSearch: React.FC<UserSearchProps> = ({ onSelectUser }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed) {
      setResults([]);
      setError(null);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.searchUsers(trimmed);
        setResults(res.users);
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query]);

  const handleSelect = async (u: User) => {
    await onSelectUser(u);
    setQuery('');
    setResults([]);
  };

  return (
    <div className="relative p-3 border-b border-gray-800">
      <div className="relative">
        <svg
          className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
          />
        </svg>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search users by username..."
          className="w-full bg-[#0a0a0f] border border-gray-800 rounded-lg pl-9 pr-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition"
        />
      </div>

      {query.trim().length > 0 && (
        <div className="mt-2 bg-[#0a0a0f] border border-gray-800 rounded-lg overflow-hidden max-h-56 overflow-y-auto shadow-xl">
          {loading && (
            <div className="px-3 py-2.5 text-xs text-gray-400">Searching...</div>
          )}
          {error && (
            <div className="px-3 py-2.5 text-xs text-red-400">{error}</div>
          )}
          {!loading && !error && results.length === 0 && (
            <div className="px-3 py-2.5 text-xs text-gray-500">
              No users found matching "{query}"
            </div>
          )}
          {!loading &&
            results.map((u) => (
              <button
                key={u.id}
                type="button"
                onClick={() => handleSelect(u)}
                className="w-full text-left px-3 py-2.5 hover:bg-gray-800/60 flex items-center justify-between transition cursor-pointer"
              >
                <div className="flex items-center gap-2.5">
                  <OnlineIndicator isOnline={u.is_online} />
                  <span className="text-sm text-gray-200 font-medium">
                    {u.username}
                  </span>
                </div>
                <span className="text-xs text-cyan-400 font-mono">Chat →</span>
              </button>
            ))}
        </div>
      )}
    </div>
  );
};
