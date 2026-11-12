import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import { CryptoIdentity, HandshakeStatus, SessionKeys } from '../types';
import * as api from '../services/api';
import {
  generateSigningKeyPair,
  initCrypto,
  isCryptoReady,
  uint8ArrayToBase64,
} from '../crypto/pq-crypto';
import {
  decryptPrivateKeyFromBackup,
  encryptPrivateKeyForBackup,
  loadIdentityFromIndexedDB,
  saveIdentityToIndexedDB,
} from '../crypto/key-management';
import {
  completeHandshakeInitiation,
  createHandshakeInitiation,
  PendingInitiatorHandshake,
  ReplayProtector,
  respondToHandshake,
} from '../crypto/handshake';
import { decrypt, encrypt } from '../crypto/symmetric';
import { socketService } from '../services/socket';
import { useAuth } from './AuthContext';

interface CryptoContextValue {
  cryptoReady: boolean;
  cryptoError: string | null;
  cryptoIdentity: CryptoIdentity | null;
  caPublicKey: string | null;
  crl: string[];
  sessionKeys: Map<string, SessionKeys>;
  handshakeStates: Map<string, HandshakeStatus>;
  initializeCryptoModule: () => Promise<void>;
  initializeIdentityForRegistration: (
    userId: string,
    password: string,
    onProgress?: (step: string) => void
  ) => Promise<CryptoIdentity>;
  restoreIdentityOnLogin: (
    userId: string,
    password?: string
  ) => Promise<CryptoIdentity | null>;
  performHandshake: (conversationId: string, peerId: string) => Promise<void>;
  handleIncomingHandshakeInitiate: (data: {
    fromUserId: string;
    kemPublicKey: string;
    signedKemPublicKey: string;
    conversationId?: string;
  }) => Promise<void>;
  handleIncomingHandshakeRespond: (data: {
    fromUserId: string;
    encapsulatedKey: string;
    signedEncapsulatedKey: string;
    conversationId?: string;
  }) => Promise<void>;
  encryptForConversation: (
    conversationId: string,
    plaintext: string,
    metadata?: Record<string, any>
  ) => Promise<{
    ciphertext: string;
    nonce: string;
    iv: string;
    tag: string;
    sequenceNumber: number;
  }>;
  decryptForConversation: (
    conversationId: string,
    ciphertext: string,
    nonce: string,
    tag: string,
    sequenceNumber: number,
    metadata?: Record<string, any>,
    options?: { messageId?: string; isHistorical?: boolean; isOwn?: boolean }
  ) => Promise<string>;
  revokeOwnCertificate: () => Promise<void>;
  regenerateIdentity: (password?: string) => Promise<CryptoIdentity>;
  refreshCAInfo: () => Promise<void>;
  seedConversationSequence: (conversationId: string, maxOwnSeq: number) => void;
}

const CryptoContext = createContext<CryptoContextValue | undefined>(undefined);

export const CryptoProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { user, isAuthenticated } = useAuth();
  const [cryptoReady, setCryptoReady] = useState(isCryptoReady());
  const [cryptoError, setCryptoError] = useState<string | null>(null);
  const [cryptoIdentity, setCryptoIdentity] = useState<CryptoIdentity | null>(null);
  const [caPublicKey, setCaPublicKey] = useState<string | null>(null);
  const [crl, setCrl] = useState<string[]>([]);
  const [sessionKeys, setSessionKeys] = useState<Map<string, SessionKeys>>(
    () => new Map()
  );
  const [handshakeStates, setHandshakeStates] = useState<
    Map<string, HandshakeStatus>
  >(() => new Map());

  const pendingHandshakesRef = useRef<Map<string, PendingInitiatorHandshake>>(
    new Map()
  );
  const replayProtectorRef = useRef<ReplayProtector>(new ReplayProtector());
  const maxOwnSeqRef = useRef<Map<string, number>>(new Map());
  const sessionKeysRef = useRef<Map<string, SessionKeys>>(sessionKeys);
  sessionKeysRef.current = sessionKeys;

  const initializeCryptoModule = useCallback(async () => {
    try {
      await initCrypto();
      setCryptoReady(true);
      setCryptoError(null);
    } catch (err) {
      setCryptoError((err as Error).message || 'Failed to initialize liboqs WASM');
      throw err;
    }
  }, []);

  const refreshCAInfo = useCallback(async () => {
    try {
      const [{ publicKey }, { crl: list }] = await Promise.all([
        api.getCAPublicKey(),
        api.getCRL(),
      ]);
      setCaPublicKey(publicKey);
      setCrl(list);
    } catch {
      // Backend might be offline on landing page; retry on auth
    }
  }, []);

  // Initialize WASM module and CA info on mount
  useEffect(() => {
    initializeCryptoModule().catch(() => {});
    refreshCAInfo().catch(() => {});
  }, [initializeCryptoModule, refreshCAInfo]);

  // Restore identity from IndexedDB when session exists, clear on logout
  useEffect(() => {
    if (!isAuthenticated || !user) {
      setCryptoIdentity(null);
      setSessionKeys(new Map());
      setHandshakeStates(new Map());
      pendingHandshakesRef.current.clear();
      return;
    }

    refreshCAInfo().catch(() => {});
    loadIdentityFromIndexedDB(user.id)
      .then((loaded) => {
        if (loaded) setCryptoIdentity(loaded);
      })
      .catch(() => {});
  }, [isAuthenticated, user, refreshCAInfo]);

  const initializeIdentityForRegistration = useCallback(
    async (
      userId: string,
      password: string,
      onProgress?: (step: string) => void
    ): Promise<CryptoIdentity> => {
      onProgress?.('Loading post-quantum WASM module (ML-DSA-65)...');
      await initializeCryptoModule();

      onProgress?.('Generating ML-DSA-65 signing key pair...');
      const signingKeyPair = await generateSigningKeyPair();
      const publicSigningKeyB64 = uint8ArrayToBase64(signingKeyPair.publicKey);

      onProgress?.('Requesting CA-signed post-quantum certificate...');
      const certificate = await api.issueCertificate(publicSigningKeyB64);

      const identity: CryptoIdentity = { signingKeyPair, certificate };

      onProgress?.('Saving private key to IndexedDB keystore...');
      await saveIdentityToIndexedDB(userId, identity);

      onProgress?.('Encrypting private key backup with PBKDF2 + AES-256-GCM...');
      const backup = await encryptPrivateKeyForBackup(
        signingKeyPair.secretKey,
        password
      );
      await api.backupKeys(backup.encryptedPrivateKey, backup.salt, backup.iv);

      setCryptoIdentity(identity);
      await refreshCAInfo();
      return identity;
    },
    [initializeCryptoModule, refreshCAInfo]
  );

  const restoreIdentityOnLogin = useCallback(
    async (userId: string, password?: string): Promise<CryptoIdentity | null> => {
      await initializeCryptoModule();
      await refreshCAInfo();

      // 1. Try IndexedDB first
      const localIdentity = await loadIdentityFromIndexedDB(userId);
      if (localIdentity) {
        setCryptoIdentity(localIdentity);
        return localIdentity;
      }

      // 2. Fallback to encrypted server backup if password provided
      if (password) {
        try {
          const [{ backup }, cert] = await Promise.all([
            api.getKeyBackup(),
            api.getUserCertificate(userId),
          ]);
          const secretKey = await decryptPrivateKeyFromBackup(
            backup.encrypted_private_key,
            backup.salt,
            backup.iv,
            password
          );
          const publicKey = Uint8Array.from(atob(cert.publicSigningKey), (c) =>
            c.charCodeAt(0)
          );
          const restored: CryptoIdentity = {
            signingKeyPair: { publicKey, secretKey },
            certificate: cert,
          };
          await saveIdentityToIndexedDB(userId, restored);
          setCryptoIdentity(restored);
          return restored;
        } catch {
          // No backup or cert revoked/missing
        }
      }

      return null;
    },
    [initializeCryptoModule, refreshCAInfo]
  );

  const setHandshakeState = useCallback(
    (conversationId: string, status: HandshakeStatus) => {
      setHandshakeStates((prev) => {
        const next = new Map(prev);
        next.set(conversationId, status);
        return next;
      });
    },
    []
  );

  const performHandshake = useCallback(
    async (conversationId: string, peerId: string) => {
      if (!cryptoIdentity) {
        throw new Error('Local cryptographic identity not initialized');
      }
      await initializeCryptoModule();
      setHandshakeState(conversationId, { state: 'initiating' });

      try {
        const { pending, payload } = await createHandshakeInitiation(
          cryptoIdentity,
          conversationId,
          peerId
        );
        pendingHandshakesRef.current.set(conversationId, pending);
        socketService.initiateHandshake(payload);
      } catch (err) {
        setHandshakeState(conversationId, {
          state: 'failed',
          error: (err as Error).message,
        });
        throw err;
      }
    },
    [cryptoIdentity, initializeCryptoModule, setHandshakeState]
  );

  const handleIncomingHandshakeInitiate = useCallback(
    async (data: {
      fromUserId: string;
      kemPublicKey: string;
      signedKemPublicKey: string;
      conversationId?: string;
    }) => {
      if (!cryptoIdentity || !data.conversationId) return;
      const convId = data.conversationId;
      setHandshakeState(convId, { state: 'responding' });

      try {
        await initializeCryptoModule();
        let currentCaKey = caPublicKey;
        let currentCrl = crl;
        if (!currentCaKey) {
          const [caRes, crlRes] = await Promise.all([
            api.getCAPublicKey(),
            api.getCRL(),
          ]);
          currentCaKey = caRes.publicKey;
          currentCrl = crlRes.crl;
          setCaPublicKey(currentCaKey);
          setCrl(currentCrl);
        }

        const peerCert = await api.getUserCertificate(data.fromUserId);
        const { sessionKeys: keys, payload } = await respondToHandshake(
          cryptoIdentity,
          convId,
          data.fromUserId,
          peerCert,
          currentCaKey,
          currentCrl,
          data.kemPublicKey,
          data.signedKemPublicKey
        );

        setSessionKeys((prev) => {
          const next = new Map(prev);
          next.set(convId, keys);
          return next;
        });
        replayProtectorRef.current.resetConversation(convId);

        setHandshakeState(convId, {
          state: 'established',
          establishedAt: keys.establishedAt,
          peerFingerprint: keys.peerFingerprint,
        });

        socketService.respondHandshake(payload);
      } catch (err) {
        setHandshakeState(convId, {
          state: 'failed',
          error: (err as Error).message,
        });
      }
    },
    [caPublicKey, crl, cryptoIdentity, initializeCryptoModule, setHandshakeState]
  );

  const handleIncomingHandshakeRespond = useCallback(
    async (data: {
      fromUserId: string;
      encapsulatedKey: string;
      signedEncapsulatedKey: string;
      conversationId?: string;
    }) => {
      if (!cryptoIdentity || !data.conversationId) return;
      const convId = data.conversationId;
      const pending = pendingHandshakesRef.current.get(convId);
      if (!pending || pending.peerId !== data.fromUserId) return;

      try {
        await initializeCryptoModule();
        let currentCaKey = caPublicKey;
        let currentCrl = crl;
        if (!currentCaKey) {
          const [caRes, crlRes] = await Promise.all([
            api.getCAPublicKey(),
            api.getCRL(),
          ]);
          currentCaKey = caRes.publicKey;
          currentCrl = crlRes.crl;
          setCaPublicKey(currentCaKey);
          setCrl(currentCrl);
        }

        const peerCert = await api.getUserCertificate(data.fromUserId);
        const keys = await completeHandshakeInitiation(
          cryptoIdentity,
          pending,
          peerCert,
          currentCaKey,
          currentCrl,
          data.encapsulatedKey,
          data.signedEncapsulatedKey
        );

        pendingHandshakesRef.current.delete(convId);
        replayProtectorRef.current.resetConversation(convId);
        setSessionKeys((prev) => {
          const next = new Map(prev);
          next.set(convId, keys);
          return next;
        });
        replayProtectorRef.current.resetConversation(convId);
        setHandshakeState(convId, {
          state: 'established',
          establishedAt: keys.establishedAt,
          peerFingerprint: keys.peerFingerprint,
        });
      } catch (err) {
        setHandshakeState(convId, {
          state: 'failed',
          error: (err as Error).message,
        });
      }
    },
    [caPublicKey, crl, cryptoIdentity, initializeCryptoModule, setHandshakeState]
  );

  const seedConversationSequence = useCallback(
    (conversationId: string, maxOwnSeq: number) => {
      const prevMax = maxOwnSeqRef.current.get(conversationId) ?? 0;
      if (maxOwnSeq > prevMax) {
        maxOwnSeqRef.current.set(conversationId, maxOwnSeq);
      }
    },
    []
  );

  const encryptForConversation = useCallback(
    async (
      conversationId: string,
      plaintext: string,
      metadata?: Record<string, any>
    ) => {
      const session = sessionKeysRef.current.get(conversationId);
      if (!session) {
        throw new Error('No established PQ session key for this conversation');
      }

      const knownMax = maxOwnSeqRef.current.get(conversationId) ?? 0;
      const nextSeq = Math.max(session.sequenceNumber, knownMax) + 1;
      maxOwnSeqRef.current.set(conversationId, nextSeq);
      const encrypted = await encrypt(plaintext, session.sendKey, nextSeq, metadata);

      setSessionKeys((prev) => {
        const next = new Map(prev);
        const existing = next.get(conversationId);
        if (existing) {
          next.set(conversationId, { ...existing, sequenceNumber: nextSeq });
        }
        return next;
      });

      return { ...encrypted, sequenceNumber: nextSeq };
    },
    []
  );

  const decryptForConversation = useCallback(
    async (
      conversationId: string,
      ciphertext: string,
      nonce: string,
      tag: string,
      sequenceNumber: number,
      metadata?: Record<string, any>,
      options?: { messageId?: string; isHistorical?: boolean; isOwn?: boolean }
    ) => {
      const session = sessionKeysRef.current.get(conversationId);
      if (!session) {
        throw new Error('Session key not established');
      }

      if (options?.messageId && !options.isOwn) {
        if (options.isHistorical) {
          replayProtectorRef.current.recordHistorical(
            conversationId,
            options.messageId,
            sequenceNumber
          );
        } else {
          replayProtectorRef.current.verifyAndTrackIncoming(
            conversationId,
            options.messageId,
            sequenceNumber
          );
        }
      }

      // Try receiveKey first (peer -> us), fallback to sendKey (our own echoed messages)
      try {
        return await decrypt(
          ciphertext,
          nonce,
          tag,
          session.receiveKey,
          sequenceNumber,
          metadata
        );
      } catch {
        return await decrypt(
          ciphertext,
          nonce,
          tag,
          session.sendKey,
          sequenceNumber,
          metadata
        );
      }
    },
    []
  );

  const revokeOwnCertificate = useCallback(async () => {
    await api.revokeCertificate();
    setCryptoIdentity((prev) =>
      prev
        ? {
            ...prev,
            certificate: { ...prev.certificate, isRevoked: true },
          }
        : null
    );
    await refreshCAInfo();
  }, [refreshCAInfo]);

  const regenerateIdentity = useCallback(
    async (password?: string): Promise<CryptoIdentity> => {
      if (!user) throw new Error('Not authenticated');
      await initializeCryptoModule();
      const signingKeyPair = await generateSigningKeyPair();
      const publicSigningKeyB64 = uint8ArrayToBase64(signingKeyPair.publicKey);
      const certificate = await api.issueCertificate(publicSigningKeyB64);
      const identity: CryptoIdentity = { signingKeyPair, certificate };
      await saveIdentityToIndexedDB(user.id, identity);
      if (password) {
        const backup = await encryptPrivateKeyForBackup(
          signingKeyPair.secretKey,
          password
        );
        await api.backupKeys(backup.encryptedPrivateKey, backup.salt, backup.iv);
      }
      setCryptoIdentity(identity);
      await refreshCAInfo();
      return identity;
    },
    [user, initializeCryptoModule, refreshCAInfo]
  );

  return (
    <CryptoContext.Provider
      value={{
        cryptoReady,
        cryptoError,
        cryptoIdentity,
        caPublicKey,
        crl,
        sessionKeys,
        handshakeStates,
        initializeCryptoModule,
        initializeIdentityForRegistration,
        restoreIdentityOnLogin,
        performHandshake,
        handleIncomingHandshakeInitiate,
        handleIncomingHandshakeRespond,
        encryptForConversation,
        decryptForConversation,
        revokeOwnCertificate,
        regenerateIdentity,
        refreshCAInfo,
        seedConversationSequence,
      }}
    >
      {children}
    </CryptoContext.Provider>
  );
};

export function useCrypto(): CryptoContextValue {
  const ctx = useContext(CryptoContext);
  if (!ctx) throw new Error('useCrypto must be used within CryptoProvider');
  return ctx;
}
