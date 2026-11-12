import React from 'react';

interface OnlineIndicatorProps {
  isOnline: boolean;
  lastSeen?: string;
  showLabel?: boolean;
  size?: 'sm' | 'md';
}

export const OnlineIndicator: React.FC<OnlineIndicatorProps> = ({
  isOnline,
  lastSeen,
  showLabel = false,
  size = 'sm',
}) => {
  const dotSize = size === 'sm' ? 'w-2.5 h-2.5' : 'w-3 h-3';

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="relative inline-flex items-center justify-center">
        <span
          className={`${dotSize} rounded-full inline-block ${
            isOnline
              ? 'bg-[#00ff41] shadow-[0_0_8px_rgba(0,255,65,0.7)] pulse-online'
              : 'bg-gray-500'
          }`}
        />
      </span>
      {showLabel && (
        <span
          className={`text-xs ${
            isOnline ? 'text-[#00ff41] font-medium' : 'text-gray-400'
          }`}
        >
          {isOnline
            ? 'Online'
            : lastSeen
              ? `Last seen ${new Date(lastSeen).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                })}`
              : 'Offline'}
        </span>
      )}
    </span>
  );
};
