import React from 'react';
import { Conversation, HandshakeStatus } from '../types';
import { OnlineIndicator } from './OnlineIndicator';

interface ConversationListProps {
  conversations: Conversation[];
  selectedId: string | null;
  onSelect: (conversation: Conversation) => void;
  handshakeStates: Map<string, HandshakeStatus>;
  typingUsers: Set<string>;
}

export const ConversationList: React.FC<ConversationListProps> = ({
  conversations,
  selectedId,
  onSelect,
  handshakeStates,
  typingUsers,
}) => {
  if (conversations.length === 0) {
    return (
      <div className="p-6 text-center text-sm text-gray-500">
        No conversations yet. Search for a user above to start a post-quantum encrypted chat.
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-800/70">
      {conversations.map((conv) => {
        const isSelected = conv.id === selectedId;
        const hs = handshakeStates.get(conv.id);
        const isEncrypted = hs?.state === 'established';
        const isTyping = typingUsers.has(conv.otherUser.id);
        const timestamp = conv.lastMessage?.createdAt || conv.updatedAt;

        return (
          <button
            key={conv.id}
            type="button"
            onClick={() => onSelect(conv)}
            className={`w-full text-left px-4 py-3.5 transition flex items-start gap-3 cursor-pointer ${
              isSelected
                ? 'bg-cyan-950/40 border-l-2 border-cyan-400'
                : 'hover:bg-gray-800/40 border-l-2 border-transparent'
            }`}
          >
            <div className="relative flex-shrink-0 w-10 h-10 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center text-sm font-bold text-cyan-400">
              {conv.otherUser.username.slice(0, 2).toUpperCase()}
              <span className="absolute -bottom-0.5 -right-0.5">
                <OnlineIndicator isOnline={conv.otherUser.is_online} />
              </span>
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-sm text-gray-100 truncate flex items-center gap-1.5">
                  {conv.otherUser.username}
                  {isEncrypted && (
                    <span
                      className="text-[#00ff41] text-[10px] font-mono"
                      title="PQ Session Key Established"
                    >
                      [E2EE]
                    </span>
                  )}
                </span>
                {timestamp && (
                  <span className="text-[11px] text-gray-500 flex-shrink-0">
                    {new Date(timestamp).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between gap-2 mt-1">
                <p className="text-xs text-gray-400 truncate">
                  {isTyping ? (
                    <span className="text-cyan-400 italic">typing...</span>
                  ) : conv.lastMessage ? (
                    <span className="font-mono text-[11px] text-gray-500">
                      Encrypted message
                    </span>
                  ) : (
                    <span className="text-gray-500">No messages yet</span>
                  )}
                </p>

                {conv.unreadCount > 0 && (
                  <span className="px-1.5 py-0.5 min-w-[20px] text-center rounded-full bg-cyan-500 text-gray-950 text-[10px] font-bold">
                    {conv.unreadCount}
                  </span>
                )}
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
};
