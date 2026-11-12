import React, { createContext, useContext, useEffect, useState } from 'react';
import { Socket } from 'socket.io-client';
import { socketService } from '../services/socket';
import { useAuth } from './AuthContext';
import { useCrypto } from './CryptoContext';

interface SocketContextValue {
  socket: Socket | null;
  connected: boolean;
}

const SocketContext = createContext<SocketContextValue | undefined>(undefined);

export const SocketProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { isAuthenticated, token } = useAuth();
  const { handleIncomingHandshakeInitiate, handleIncomingHandshakeRespond } =
    useCrypto();
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      socketService.disconnect();
      setSocket(null);
      setConnected(false);
      return;
    }

    const s = socketService.connect(token || undefined);
    setSocket(s);
    setConnected(s.connected);

    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);

    s.on('connect', onConnect);
    s.on('disconnect', onDisconnect);

    return () => {
      s.off('connect', onConnect);
      s.off('disconnect', onDisconnect);
    };
  }, [isAuthenticated, token]);

  // Wire global PQ handshake listeners whenever authenticated & connected
  useEffect(() => {
    if (!isAuthenticated || !socket) return;

    const unsubInit = socketService.onHandshakeInitiate((data) => {
      handleIncomingHandshakeInitiate(data).catch((err) => {
        console.error('[PQ Handshake] Respond failed:', err.message);
      });
    });

    const unsubResp = socketService.onHandshakeRespond((data) => {
      handleIncomingHandshakeRespond(data).catch((err) => {
        console.error('[PQ Handshake] Complete failed:', err.message);
      });
    });

    return () => {
      unsubInit();
      unsubResp();
    };
  }, [
    isAuthenticated,
    socket,
    handleIncomingHandshakeInitiate,
    handleIncomingHandshakeRespond,
  ]);

  return (
    <SocketContext.Provider value={{ socket, connected }}>
      {children}
    </SocketContext.Provider>
  );
};

export function useSocket(): SocketContextValue {
  const ctx = useContext(SocketContext);
  if (!ctx) throw new Error('useSocket must be used within SocketProvider');
  return ctx;
}
