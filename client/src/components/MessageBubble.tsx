import React from 'react';
import { Message } from '../types';

interface MessageBubbleProps {
  message: Message;
  isOwn: boolean;
}

export const MessageBubble: React.FC<MessageBubbleProps> = ({
  message,
  isOwn,
}) => {
  const timeStr = message.createdAt
    ? new Date(message.createdAt).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      })
    : '';

  const renderStatus = () => {
    if (!isOwn) return null;
    switch (message.status) {
      case 'sending':
        return <span className="text-gray-400">•••</span>;
      case 'sent':
        return <span className="text-gray-400" title="Sent">✓</span>;
      case 'delivered':
        return <span className="text-gray-300" title="Delivered">✓✓</span>;
      case 'read':
        return <span className="text-[#00ff41]" title="Read">✓✓</span>;
      case 'failed':
        return <span className="text-red-400" title="Failed">!</span>;
      default:
        return null;
    }
  };

  return (
    <div
      className={`flex flex-col message-enter ${
        isOwn ? 'items-end' : 'items-start'
      }`}
    >
      <div
        className={`max-w-[78%] sm:max-w-[68%] rounded-2xl px-4 py-2.5 border ${
          isOwn
            ? 'bg-cyan-950/60 border-cyan-500/30 text-gray-100 rounded-br-sm'
            : 'bg-[#111827] border-gray-800 text-gray-200 rounded-bl-sm'
        }`}
      >
        {message.plaintext !== undefined ? (
          <p className="text-sm whitespace-pre-wrap break-words leading-relaxed">
            {message.plaintext}
          </p>
        ) : (
          <div className="space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-amber-400 font-mono">
              <svg
                className="w-3.5 h-3.5 flex-shrink-0"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
              <span>
                {message.decryptionError ||
                  'Encrypted payload (session key unavailable)'}
              </span>
            </div>
            <p className="font-mono text-[10px] text-gray-500 truncate max-w-xs">
              {message.ciphertext}
            </p>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 mt-1 text-[10px] text-gray-400">
          {message.sequenceNumber > 0 && (
            <span className="font-mono text-gray-500">
              #{message.sequenceNumber}
            </span>
          )}
          <span>{timeStr}</span>
          {renderStatus()}
        </div>
      </div>
    </div>
  );
};
