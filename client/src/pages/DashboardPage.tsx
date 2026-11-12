import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Conversation, Message, User } from '../types';
import * as api from '../services/api';
import { socketService } from '../services/socket';
import { useAuth } from '../contexts/AuthContext';
import { useCrypto } from '../contexts/CryptoContext';
import { useSocket } from '../contexts/SocketContext';
import { Layout } from '../components/Layout';
import { UserSearch } from '../components/UserSearch';
import { ConversationList } from '../components/ConversationList';
import { OnlineIndicator } from '../components/OnlineIndicator';
import { EncryptionBadge } from '../components/EncryptionBadge';
import { MessageBubble } from '../components/MessageBubble';
import { MessageInput } from '../components/MessageInput';

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const { connected } = useSocket();
  const {
    cryptoIdentity,
    sessionKeys,
    handshakeStates,
    performHandshake,
    encryptForConversation,
    decryptForConversation,
    seedConversationSequence,
  } = useCrypto();

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConvId, setSelectedConvId] = useState<string | null>(null);
  const [messagesByConv, setMessagesByConv] = useState<Map<string, Message[]>>(
    () => new Map()
  );
  const [typingUsers, setTypingUsers] = useState<Set<string>>(() => new Set());
  const [loadingConvs, setLoadingConvs] = useState(true);
  const [loadingMsgs, setLoadingMsgs] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mobileShowChat, setMobileShowChat] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const selectedConvIdRef = useRef<string | null>(selectedConvId);
  selectedConvIdRef.current = selectedConvId;

  const selectedConversation =
    conversations.find((c) => c.id === selectedConvId) || null;
  const activeMessages = selectedConvId
    ? messagesByConv.get(selectedConvId) || []
    : [];
  const activeSession = selectedConvId ? sessionKeys.get(selectedConvId) : undefined;
  const activeHandshake = selectedConvId
    ? handshakeStates.get(selectedConvId)
    : undefined;

  const loadConversations = useCallback(async () => {
    try {
      const { conversations: list } = await api.getConversations();
      setConversations(list);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingConvs(false);
    }
  }, []);

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  // Decrypt messages for a conversation whenever session keys arrive
  const decryptMessageList = useCallback(
    async (convId: string, msgs: Message[], isHistorical: boolean) => {
      if (!sessionKeys.has(convId)) return msgs;
      return Promise.all(
        msgs.map(async (m) => {
          if (m.plaintext !== undefined) return m;
          try {
            const pt = await decryptForConversation(
              convId,
              m.ciphertext,
              m.nonce || m.iv,
              m.tag,
              m.sequenceNumber,
              m.metadata || undefined,
              {
                messageId: m.id,
                isHistorical,
                isOwn: m.senderId === user?.id,
              }
            );
            return { ...m, plaintext: pt, decryptionError: undefined };
          } catch (err) {
            return {
              ...m,
              decryptionError:
                (err as Error).message || 'Unable to decrypt with current session key',
            };
          }
        })
      );
    },
    [decryptForConversation, sessionKeys, user?.id]
  );

  // Load messages when selecting a conversation
  useEffect(() => {
    if (!selectedConvId) return;
    let cancelled = false;
    setLoadingMsgs(true);

    (async () => {
      try {
        const { messages, myLastSequenceNumber } =
          await api.getMessages(selectedConvId);
        const scannedMaxSeq = messages.reduce((max, m) => {
          if (m.senderId === user?.id && m.sequenceNumber > max) {
            return m.sequenceNumber;
          }
          return max;
        }, 0);
        const maxOwnSeq =
          myLastSequenceNumber !== undefined
            ? Math.max(myLastSequenceNumber, scannedMaxSeq)
            : scannedMaxSeq;
        if (maxOwnSeq > 0) {
          seedConversationSequence(selectedConvId, maxOwnSeq);
        }
        const decrypted = await decryptMessageList(selectedConvId, messages, true);
        if (!cancelled) {
          setMessagesByConv((prev) => {
            const next = new Map(prev);
            next.set(selectedConvId, decrypted);
            return next;
          });
          // Mark unread peer messages as read
          for (const m of messages) {
            if (m.senderId !== user?.id && m.status !== 'read') {
              socketService.markRead(m.id, selectedConvId);
            }
          }
          setConversations((prev) =>
            prev.map((c) => (c.id === selectedConvId ? { ...c, unreadCount: 0 } : c))
          );
        }
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      } finally {
        if (!cancelled) setLoadingMsgs(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [selectedConvId, user?.id]);

  // Re-try decrypting loaded messages when a PQ session key finishes establishing
  useEffect(() => {
    if (!selectedConvId || !activeSession) return;
    const currentMsgs = messagesByConv.get(selectedConvId);
    if (!currentMsgs || currentMsgs.length === 0) return;
    if (currentMsgs.every((m) => m.plaintext !== undefined)) return;

    decryptMessageList(selectedConvId, currentMsgs, true).then((updated) => {
      setMessagesByConv((prev) => {
        const next = new Map(prev);
        next.set(selectedConvId, updated);
        return next;
      });
    });
  }, [selectedConvId, activeSession, decryptMessageList]);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeMessages.length]);

  // Socket real-time listeners
  useEffect(() => {
    if (!connected) return;

    const unsubMsg = socketService.onMessage(async (incoming) => {
      const convId = incoming.conversationId;
      const isOwn = incoming.senderId === user?.id;

      let processed: Message = incoming;
      if (sessionKeys.has(convId)) {
        try {
          const plaintext = await decryptForConversation(
            convId,
            incoming.ciphertext,
            incoming.nonce || incoming.iv,
            incoming.tag,
            incoming.sequenceNumber,
            incoming.metadata || undefined,
            { messageId: incoming.id, isHistorical: false, isOwn }
          );
          processed = { ...incoming, plaintext };
        } catch (err) {
          processed = {
            ...incoming,
            decryptionError: (err as Error).message,
          };
        }
      }

      setMessagesByConv((prev) => {
        const next = new Map(prev);
        const existing = next.get(convId) || [];
        const duplicateIdx = existing.findIndex(
          (m) =>
            m.id === processed.id ||
            (incoming.clientMessageId && m.id === incoming.clientMessageId)
        );
        if (duplicateIdx >= 0) {
          const copy = [...existing];
          copy[duplicateIdx] = {
            ...processed,
            plaintext: copy[duplicateIdx].plaintext ?? processed.plaintext,
          };
          next.set(convId, copy);
        } else {
          next.set(convId, [...existing, processed]);
        }
        return next;
      });

      if (!isOwn) {
        if (selectedConvIdRef.current === convId) {
          socketService.markRead(incoming.id, convId);
        } else {
          socketService.markDelivered(incoming.id, convId);
        }
      }

      setConversations((prev) => {
        const found = prev.some((c) => c.id === convId);
        if (!found) {
          loadConversations();
          return prev;
        }
        return prev
          .map((c) => {
            if (c.id !== convId) return c;
            const isViewing = selectedConvIdRef.current === convId;
            return {
              ...c,
              updatedAt: incoming.createdAt,
              unreadCount: !isOwn && !isViewing ? c.unreadCount + 1 : 0,
              lastMessage: {
                id: incoming.id,
                ciphertext: incoming.ciphertext,
                createdAt: incoming.createdAt,
                senderId: incoming.senderId,
                status: incoming.status,
              },
            };
          })
          .sort(
            (a, b) =>
              new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
          );
      });
    });

    const unsubDelivered = socketService.onDelivered(
      ({ messageId, conversationId, status, deliveredAt }) => {
        setMessagesByConv((prev) => {
          const next = new Map(prev);
          const list = next.get(conversationId);
          if (!list) return prev;
          next.set(
            conversationId,
            list.map((m) =>
              m.id === messageId
                ? { ...m, status: status as Message['status'], deliveredAt }
                : m
            )
          );
          return next;
        });
      }
    );

    const unsubRead = socketService.onRead(
      ({ messageId, conversationId, status, readAt }) => {
        setMessagesByConv((prev) => {
          const next = new Map(prev);
          const list = next.get(conversationId);
          if (!list) return prev;
          next.set(
            conversationId,
            list.map((m) =>
              m.id === messageId
                ? { ...m, status: status as Message['status'], readAt }
                : m
            )
          );
          return next;
        });
      }
    );

    const unsubOnline = socketService.onUserOnline(({ userId }) => {
      setConversations((prev) =>
        prev.map((c) =>
          c.otherUser.id === userId
            ? { ...c, otherUser: { ...c.otherUser, is_online: true } }
            : c
        )
      );
    });

    const unsubOffline = socketService.onUserOffline(({ userId, lastSeen }) => {
      setConversations((prev) =>
        prev.map((c) =>
          c.otherUser.id === userId
            ? {
                ...c,
                otherUser: {
                  ...c.otherUser,
                  is_online: false,
                  last_seen: lastSeen,
                },
              }
            : c
        )
      );
    });

    const unsubTyping = socketService.onTyping(({ userId, isTyping }) => {
      setTypingUsers((prev) => {
        const next = new Set(prev);
        if (isTyping) next.add(userId);
        else next.delete(userId);
        return next;
      });
    });

    return () => {
      unsubMsg();
      unsubDelivered();
      unsubRead();
      unsubOnline();
      unsubOffline();
      unsubTyping();
    };
  }, [connected, decryptForConversation, loadConversations, sessionKeys, user?.id]);

  const handleSelectConversation = (conv: Conversation) => {
    setSelectedConvId(conv.id);
    setMobileShowChat(true);
    setError(null);
  };

  const handleStartConversationWithUser = async (targetUser: User) => {
    setError(null);
    try {
      const { conversation } = await api.createConversation(targetUser.id);
      await loadConversations();
      setSelectedConvId(conversation.id);
      setMobileShowChat(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleInitiateHandshake = async () => {
    if (!selectedConversation) return;
    setError(null);
    try {
      await performHandshake(
        selectedConversation.id,
        selectedConversation.otherUser.id
      );
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleSendMessage = async (plaintext: string) => {
    if (!selectedConversation || !user) return;
    setError(null);

    const convId = selectedConversation.id;
    const recipientId = selectedConversation.otherUser.id;
    const tempId = crypto.randomUUID();
    const metadata = { senderId: user.id, timestamp: Date.now() };

    const encrypted = await encryptForConversation(convId, plaintext, metadata);

    const optimistic: Message = {
      id: tempId,
      conversationId: convId,
      senderId: user.id,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      iv: encrypted.iv,
      tag: encrypted.tag,
      sequenceNumber: encrypted.sequenceNumber,
      metadata,
      createdAt: new Date().toISOString(),
      status: 'sending',
      plaintext,
    };

    setMessagesByConv((prev) => {
      const next = new Map(prev);
      next.set(convId, [...(next.get(convId) || []), optimistic]);
      return next;
    });

    socketService.sendEncryptedMessage(
      {
        conversationId: convId,
        recipientId,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        iv: encrypted.iv,
        tag: encrypted.tag,
        sequenceNumber: encrypted.sequenceNumber,
        metadata,
        messageId: tempId,
      },
      (ack) => {
        if (ack?.error) {
          setMessagesByConv((prev) => {
            const next = new Map(prev);
            const list = next.get(convId) || [];
            next.set(
              convId,
              list.map((m) => (m.id === tempId ? { ...m, status: 'failed' } : m))
            );
            return next;
          });
          setError(ack.error);
          return;
        }
        if (ack?.ok && ack.message) {
          setMessagesByConv((prev) => {
            const next = new Map(prev);
            const list = next.get(convId) || [];
            next.set(
              convId,
              list.map((m) =>
                m.id === tempId
                  ? {
                      ...m,
                      id: ack.message.id || m.id,
                      status: ack.message.status || 'sent',
                      createdAt: ack.message.created_at || m.createdAt,
                    }
                  : m
              )
            );
            return next;
          });
        }
      }
    );
  };

  return (
    <Layout>
      {!cryptoIdentity && (
        <div className="bg-amber-950/60 border-b border-amber-500/40 px-4 py-2 text-xs text-amber-200 flex items-center justify-between">
          <span>
            No local ML-DSA-65 signing key found in IndexedDB for this browser session.
          </span>
          <Link
            to="/security"
            className="px-2.5 py-1 rounded bg-amber-500/20 border border-amber-400/50 text-amber-300 hover:bg-amber-500/30 font-medium"
          >
            Generate / Restore Keys →
          </Link>
        </div>
      )}

      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left Sidebar */}
        <aside
          className={`w-full md:w-80 lg:w-96 border-r border-gray-800 bg-[#111827]/60 flex flex-col flex-shrink-0 ${
            mobileShowChat ? 'hidden md:flex' : 'flex'
          }`}
        >
          <UserSearch onSelectUser={handleStartConversationWithUser} />
          <div className="px-4 py-2.5 border-b border-gray-800/70 flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
              Conversations
            </span>
            <span className="text-xs font-mono text-gray-500">
              {conversations.length}
            </span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {loadingConvs ? (
              <div className="p-6 text-center text-xs text-gray-500">
                Loading conversations...
              </div>
            ) : (
              <ConversationList
                conversations={conversations}
                selectedId={selectedConvId}
                onSelect={handleSelectConversation}
                handshakeStates={handshakeStates}
                typingUsers={typingUsers}
              />
            )}
          </div>
        </aside>

        {/* Main Chat Area */}
        <section
          className={`flex-1 flex flex-col min-w-0 bg-[#0a0a0f] ${
            mobileShowChat ? 'flex' : 'hidden md:flex'
          }`}
        >
          {selectedConversation ? (
            <>
              {/* Chat Header */}
              <div className="h-16 border-b border-gray-800 bg-[#111827]/80 px-4 sm:px-6 flex items-center justify-between gap-3 flex-shrink-0">
                <div className="flex items-center gap-3 min-w-0">
                  <button
                    type="button"
                    onClick={() => setMobileShowChat(false)}
                    className="md:hidden p-1.5 rounded-lg bg-gray-800 text-gray-300"
                  >
                    ←
                  </button>
                  <div className="w-9 h-9 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center text-xs font-bold text-cyan-400 flex-shrink-0">
                    {selectedConversation.otherUser.username.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <h2 className="font-semibold text-sm sm:text-base text-gray-100 truncate">
                        {selectedConversation.otherUser.username}
                      </h2>
                      <OnlineIndicator
                        isOnline={selectedConversation.otherUser.is_online}
                        lastSeen={selectedConversation.otherUser.last_seen}
                        showLabel
                      />
                    </div>
                    {typingUsers.has(selectedConversation.otherUser.id) && (
                      <p className="text-xs text-cyan-400 italic">typing...</p>
                    )}
                  </div>
                </div>

                <EncryptionBadge
                  status={activeHandshake}
                  onInitiateHandshake={handleInitiateHandshake}
                />
              </div>

              {error && (
                <div className="mx-4 mt-3 px-3 py-2 rounded-lg bg-red-950/60 border border-red-500/40 text-xs text-red-300 flex items-center justify-between">
                  <span>{error}</span>
                  <button
                    type="button"
                    onClick={() => setError(null)}
                    className="text-red-400 hover:text-red-200 ml-3 cursor-pointer"
                  >
                    ✕
                  </button>
                </div>
              )}

              {!activeSession && (
                <div className="mx-4 mt-3 p-3 rounded-xl bg-cyan-950/30 border border-cyan-500/30 flex flex-wrap items-center justify-between gap-3">
                  <div className="text-xs text-gray-300">
                    <span className="font-semibold text-cyan-400">
                      Post-Quantum Handshake Required:
                    </span>{' '}
                    Perform an authenticated ML-KEM-768 + ML-DSA-65 key exchange with{' '}
                    <span className="font-mono text-white">
                      {selectedConversation.otherUser.username}
                    </span>{' '}
                    (both users must be online).
                  </div>
                  <button
                    type="button"
                    onClick={handleInitiateHandshake}
                    disabled={!cryptoIdentity || !connected}
                    className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition cursor-pointer"
                  >
                    Start ML-KEM Handshake
                  </button>
                </div>
              )}

              {/* Message List */}
              <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-3">
                {loadingMsgs ? (
                  <div className="text-center text-xs text-gray-500 py-8">
                    Loading encrypted history...
                  </div>
                ) : activeMessages.length === 0 ? (
                  <div className="text-center text-xs text-gray-500 py-12 font-mono">
                    No messages yet. Establish a PQ session and send the first encrypted message.
                  </div>
                ) : (
                  activeMessages.map((msg) => (
                    <MessageBubble
                      key={msg.id}
                      message={msg}
                      isOwn={msg.senderId === user?.id}
                    />
                  ))
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* Message Input */}
              <MessageInput
                disabled={!activeSession}
                onSend={handleSendMessage}
                onTypingChange={(isTyping) =>
                  socketService.sendTyping(
                    selectedConversation.otherUser.id,
                    selectedConversation.id,
                    isTyping
                  )
                }
              />
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#00ff41]/15 to-cyan-500/15 border border-[#00ff41]/30 flex items-center justify-center">
                <svg
                  className="w-8 h-8 text-[#00ff41]"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.8}
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                  />
                </svg>
              </div>
              <div className="space-y-1 max-w-md">
                <h2 className="text-xl font-bold text-white">
                  Zero-Knowledge Post-Quantum Chat
                </h2>
                <p className="text-sm text-gray-400">
                  Select a conversation on the left or search for a user to establish
                  an ephemeral ML-KEM-768 + AES-256-GCM encrypted channel.
                </p>
              </div>
            </div>
          )}
        </section>
      </div>
    </Layout>
  );
};
