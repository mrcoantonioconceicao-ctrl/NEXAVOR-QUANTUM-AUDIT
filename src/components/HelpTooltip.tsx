import React, { useState } from 'react';
import { HelpCircle, Info } from 'lucide-react';

interface HelpTooltipProps {
  title?: string;
  content: string;
  impact?: string;
  icon?: 'help' | 'info';
  className?: string;
  position?: 'top' | 'bottom' | 'left' | 'right';
}

export const HelpTooltip: React.FC<HelpTooltipProps> = ({
  title,
  content,
  impact,
  icon = 'help',
  className = '',
  position = 'top',
}) => {
  const [isVisible, setIsVisible] = useState(false);

  const getPositionClasses = () => {
    switch (position) {
      case 'bottom':
        return 'top-full left-1/2 -translate-x-1/2 mt-2';
      case 'left':
        return 'right-full top-1/2 -translate-y-1/2 mr-2';
      case 'right':
        return 'left-full top-1/2 -translate-y-1/2 ml-2';
      case 'top':
      default:
        return 'bottom-full left-1/2 -translate-x-1/2 mb-2';
    }
  };

  return (
    <div className={`relative inline-flex items-center ${className}`}>
      <button
        type="button"
        onMouseEnter={() => setIsVisible(true)}
        onMouseLeave={() => setIsVisible(false)}
        onFocus={() => setIsVisible(true)}
        onBlur={() => setIsVisible(false)}
        className="text-zinc-500 hover:text-emerald-400 focus:outline-none transition-colors p-0.5 rounded cursor-help"
        aria-label={title || 'Informação de ajuda'}
      >
        {icon === 'help' ? (
          <HelpCircle className="h-3.5 w-3.5 text-zinc-400 hover:text-emerald-400" />
        ) : (
          <Info className="h-3.5 w-3.5 text-zinc-400 hover:text-emerald-400" />
        )}
      </button>

      {isVisible && (
        <div
          role="tooltip"
          className={`absolute z-50 w-72 max-w-xs rounded-lg border border-zinc-700 bg-zinc-900/95 p-3 text-xs text-zinc-200 shadow-xl backdrop-blur-md pointer-events-none animate-in fade-in zoom-in-95 duration-150 ${getPositionClasses()}`}
        >
          {title && (
            <div className="font-mono font-bold text-white text-[11px] uppercase tracking-wider mb-1 flex items-center gap-1.5 border-b border-zinc-800 pb-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
              <span>{title}</span>
            </div>
          )}
          <p className="text-zinc-300 font-sans leading-relaxed text-[11px]">
            {content}
          </p>
          {impact && (
            <div className="mt-2 pt-1.5 border-t border-zinc-800/80 text-[10px] font-sans text-amber-300/90 flex items-start gap-1">
              <span className="font-bold font-mono uppercase text-amber-400">Impacto:</span>
              <span>{impact}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
