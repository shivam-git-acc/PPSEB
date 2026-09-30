export function Card({ title, subtitle, actions, children, className = "", pad = true }) {
  return (
    <section className={`panel ${className}`}>
      {(title || subtitle || actions) && (
        <header className="px-5 py-3.5 border-b border-ink-800 flex items-start justify-between gap-4">
          <div className="min-w-0">
            {title && <h2 className="text-[13px] font-semibold text-ink-100 tracking-[0.01em]">{title}</h2>}
            {subtitle && <p className="text-2xs text-ink-500 mt-1 leading-relaxed">{subtitle}</p>}
          </div>
          {actions && <div className="shrink-0 flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={pad ? "p-5" : ""}>{children}</div>
    </section>
  );
}

/* A status badge always carries a word, never colour alone: the validated
   palette puts red and green 4.1 dE apart under deuteranopia. */
export function Badge({ tone = "neutral", children }) {
  const tones = {
    neutral: "bg-white/[0.06] text-ink-300 ring-white/10",
    green: "bg-signal-green/12 text-[#35c235] ring-signal-green/30",
    red: "bg-signal-red/14 text-[#e55757] ring-signal-red/35",
    amber: "bg-signal-amber/12 text-signal-amber ring-signal-amber/30",
    blue: "bg-signal-blue/14 text-[#6aa6ef] ring-signal-blue/30",
  };
  return (
    <span className={`text-2xs px-2 py-1 rounded-md font-medium ring-1 ring-inset whitespace-nowrap ${tones[tone]}`}>
      {children}
    </span>
  );
}

/* A measured value the reader must actually read. Primary ink with a coloured
   dot, rather than coloured text on a dark panel. */
export function Value({ tone = "neutral", children, className = "" }) {
  const map = { break: "is-break", ok: "is-ok", warn: "is-warn", neutral: "" };
  return <span className={`value-chip mono text-[13px] ${map[tone] ?? ""} ${className}`}>{children}</span>;
}

export function PrimaryButton({ children, ...props }) {
  return (
    <button {...props}
      className="text-[13px] font-medium rounded-lg px-4 py-2 whitespace-nowrap bg-accent hover:bg-accent-soft
                 text-ink-975 ring-1 ring-inset ring-white/15
                 disabled:opacity-35 disabled:cursor-not-allowed transition-colors">
      {children}
    </button>
  );
}

export function SecondaryButton({ children, ...props }) {
  return (
    <button {...props}
      className="text-[13px] font-medium rounded-lg px-3.5 py-2 whitespace-nowrap bg-white/[0.04] ring-1 ring-inset ring-ink-700
                 hover:bg-white/[0.08] hover:ring-ink-600 text-ink-200
                 disabled:opacity-35 disabled:cursor-not-allowed transition-colors">
      {children}
    </button>
  );
}

export function ErrorBanner({ message }) {
  if (!message) return null;
  return (
    <div className="text-xs text-[#e55757] bg-signal-red/10 ring-1 ring-inset ring-signal-red/30
                    rounded-lg px-3 py-2 mt-3">
      <span className="font-medium">Error</span> · {message}
    </div>
  );
}

/* One number, stated once, big enough to read across a room. */
export function Stat({ label, value, tone = "neutral", hint }) {
  const ink = { neutral: "text-ink-100", break: "text-[#e55757]", ok: "text-[#35c235]", warn: "text-signal-amber" };
  return (
    <div className="rounded-lg bg-white/[0.03] ring-1 ring-inset ring-ink-800 px-4 py-3">
      <div className="text-2xs uppercase tracking-[0.08em] text-ink-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tnum ${ink[tone] ?? ink.neutral}`}>{value}</div>
      {hint && <div className="text-2xs text-ink-500 mt-0.5">{hint}</div>}
    </div>
  );
}

export function Field({ label, hint, children }) {
  return (
    <label className="block">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-2xs text-ink-400">{label}</span>
        {hint && <span className="text-2xs text-ink-600">{hint}</span>}
      </div>
      <div className="mt-1.5">{children}</div>
    </label>
  );
}

export const inputCls =
  "mono text-[13px] bg-ink-950/70 ring-1 ring-inset ring-ink-700 rounded-lg px-2.5 py-1.5 " +
  "text-ink-100 focus:ring-accent focus:outline-none w-full";
