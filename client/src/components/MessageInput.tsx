import React, { useRef, useState } from 'react';

interface MessageInputProps {
  disabled: boolean;
  placeholder?: string;
  onSend: (plaintext: string) => Promise<void>;
  onTypingChange?: (isTyping: boolean) => void;
}

export const MessageInput: React.FC<MessageInputProps> = ({
  disabled,
  placeholder,
  onSend,
  onTypingChange,
}) => {
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isTypingRef = useRef(false);

  const stopTyping = () => {
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = null;
    }
    if (isTypingRef.current) {
      isTypingRef.current = false;
      onTypingChange?.(false);
    }
  };

  const handleChange = (val: string) => {
    setText(val);
    if (!onTypingChange || disabled) return;

    if (val.trim().length > 0 && !isTypingRef.current) {
      isTypingRef.current = true;
      onTypingChange(true);
    }

    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      if (isTypingRef.current) {
        isTypingRef.current = false;
        onTypingChange(false);
      }
    }, 1500);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed || disabled || sending) return;

    stopTyping();
    setSending(true);
    try {
      await onSend(trimmed);
      setText('');
    } finally {
      setSending(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="p-3 sm:p-4 border-t border-gray-800 bg-[#111827]/80 flex items-center gap-3"
    >
      <input
        type="text"
        value={text}
        onChange={(e) => handleChange(e.target.value)}
        disabled={disabled || sending}
        placeholder={
          placeholder ||
          (disabled
            ? 'Establish a post-quantum session first to send encrypted messages...'
            : 'Type an AES-256-GCM encrypted message...')
        }
        className="flex-1 bg-[#0a0a0f] border border-gray-800 rounded-xl px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 disabled:opacity-50 transition"
      />
      <button
        type="submit"
        disabled={disabled || sending || !text.trim()}
        className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-800 disabled:text-gray-500 text-white text-sm font-medium transition flex items-center gap-2 cursor-pointer disabled:cursor-not-allowed"
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
          />
        </svg>
        <span className="hidden sm:inline">{sending ? 'Encrypting...' : 'Send'}</span>
      </button>
    </form>
  );
};
