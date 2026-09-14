export function Card({ title, subtitle, children, className = "" }) {
  return (
    <div className={`border border-ink-800 rounded-lg bg-ink-900/40 ${className}`}>
      {(title || subtitle) && (
        <div className="px-4 py-3 border-b border-ink-800">
          {title && <div className="text-sm font-medium text-ink-100">{title}</div>}
          {subtitle && <div className="text-xs text-ink-400 mt-0.5">{subtitle}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

export function Badge({ tone = "neutral", children }) {
  const tones = {
    neutral: "bg-ink-800 text-ink-300",
    green: "bg-signal-green/20 text-signal-green",
    red: "bg-signal-red/20 text-signal-red",
    amber: "bg-amber-500/20 text-amber-400",
    blue: "bg-signal-blue/20 text-signal-blue",
  };
  return <span className={`text-[11px] px-2 py-0.5 rounded font-medium ${tones[tone]}`}>{children}</span>;
}

export function PrimaryButton({ children, ...props }) {
  return (
    <button
      {...props}
      className="text-sm font-medium rounded px-3.5 py-2 bg-signal-blue/90 hover:bg-signal-blue
                 text-ink-950 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    >
      {children}
    </button>
  );
}

export function SecondaryButton({ children, ...props }) {
  return (
    <button
      {...props}
      className="text-sm font-medium rounded px-3.5 py-2 border border-ink-700 hover:border-ink-500
                 text-ink-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    >
      {children}
    </button>
  );
}

export function ErrorBanner({ message }) {
  if (!message) return null;
  return (
    <div className="text-xs text-signal-red bg-signal-red/10 border border-signal-red/30 rounded px-3 py-2">
      {message}
    </div>
  );
}
