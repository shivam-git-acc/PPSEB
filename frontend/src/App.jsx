import { useEffect, useState } from "react";
import ParamsBar from "./components/ParamsBar";
import { api } from "./api";

import OverviewTab from "./tabs/OverviewTab";
import HappyPathTab from "./tabs/HappyPathTab";
import KgaTab from "./tabs/KgaTab";
import ForwardSecTab from "./tabs/ForwardSecTab";
import SpecDefectTab from "./tabs/SpecDefectTab";
import BatchSweepTab from "./tabs/BatchSweepTab";
import SecurityBoundaryTab from "./tabs/SecurityBoundaryTab";
import PublicKeyBreakTab from "./tabs/PublicKeyBreakTab";
import NetworkTab from "./tabs/NetworkTab";
import RecoveryTab from "./tabs/RecoveryTab";
import LedgerTab from "./tabs/LedgerTab";
import ProofTab from "./tabs/ProofTab";

/* Grouped so the nav reads as a story rather than ten equal buttons:
   how it works -> what is broken -> how far it goes. */
const GROUPS = [
  { name: "Scheme", tabs: [
    { id: "overview", label: "Overview" },
    { id: "happy", label: "Happy Path" },
    { id: "network", label: "Network" },
  ] },
  { name: "Findings", tabs: [
    { id: "spec", label: "Spec Defect" },
    { id: "kga", label: "KGA" },
    { id: "forward", label: "Forward Security" },
    { id: "pkbreak", label: "Public-Key" },
    { id: "ledger", label: "Ledger" },
    { id: "proof", label: "Proof" },
  ] },
  { name: "Measurement", tabs: [
    { id: "recovery", label: "Recovery" },
    { id: "boundary", label: "Boundary" },
    { id: "sweep", label: "Batch Sweep" },
  ] },
];
const ALL = GROUPS.flatMap((g) => g.tabs);

export default function App() {
  const [params, setParams] = useState({ n: 4, q: 257, sigma: 4.0, l: 10 });
  const [initialized, setInitialized] = useState(false);
  const [applying, setApplying] = useState(false);
  const [shapeTable, setShapeTable] = useState(null);
  const [maxPeriod, setMaxPeriod] = useState(0);
  // Hash routing: a tab is linkable, reload keeps your place, and the browser
  // back button works.
  const [tab, setTab] = useState(() => {
    const h = window.location.hash.replace("#", "");
    return ALL.some((t) => t.id === h) ? h : "overview";
  });
  useEffect(() => {
    const onHash = () => {
      const h = window.location.hash.replace("#", "");
      if (ALL.some((t) => t.id === h)) setTab(h);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const go = (id) => { window.location.hash = id; setTab(id); };
  const [initError, setInitError] = useState(null);

  const applyParams = async () => {
    setApplying(true);
    setInitError(null);
    try {
      const res = await api.init(params);
      setShapeTable(res.result.shape_table);
      setMaxPeriod(res.result.max_period);
      setInitialized(true);
    } catch (e) {
      setInitError(String(e.message || e));
      setInitialized(false);
    } finally {
      setApplying(false);
    }
  };

  // The trace is no longer a permanent rail; tabs that want it render it
  // inline, on demand.
  const tabProps = { onTrace: () => {}, initialized, maxPeriod, params };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="shrink-0 border-b border-ink-800 bg-ink-950/60 backdrop-blur-xl">
        <div className="mx-auto w-full max-w-[1400px] flex items-center gap-5 px-6 h-13" style={{ height: 52 }}>
          <div className="flex items-center gap-2.5 shrink-0">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden>
              <rect x="2.5" y="2.5" width="19" height="19" rx="5" stroke="#6e8cff" strokeWidth="1.5" />
              <path d="M7 15.5l3.5-7 3 4.5 3.5-3" stroke="#35c235" strokeWidth="1.6"
                    strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <div className="leading-tight">
              <div className="text-[13px] font-semibold text-ink-100 tracking-[0.01em]">PPSEB Lab</div>
              <div className="text-[10px] text-ink-500">Xu et al. 2022 · corrected &amp; attacked</div>
            </div>
          </div>
          <div className="flex-1" />
          <ParamsBar
            params={params} setParams={setParams} onApply={applyParams} applying={applying}
            initialized={initialized} shapeTable={shapeTable} maxPeriod={maxPeriod} error={initError}
          />
        </div>

        <nav className="mx-auto w-full max-w-[1400px] flex items-stretch gap-0.5 px-6 overflow-x-auto"
             aria-label="Sections">
          {GROUPS.map((g, gi) => (
            <div key={g.name} className="flex items-stretch">
              {gi > 0 && <span className="self-center mx-2 h-4 w-px bg-ink-800" aria-hidden />}
              <span className="self-center text-[10px] uppercase tracking-[0.1em] text-ink-600 mr-2.5 hidden xl:inline">
                {g.name}
              </span>
              {g.tabs.map((t) => {
                const on = tab === t.id;
                return (
                  <button key={t.id} onClick={() => go(t.id)} aria-current={on ? "page" : undefined}
                    className={`relative px-2.5 py-2.5 text-[13px] whitespace-nowrap transition-colors ${
                      on ? "text-ink-100" : "text-ink-400 hover:text-ink-200"}`}>
                    {t.label}
                    <span className={`absolute left-2.5 right-2.5 -bottom-px h-0.5 rounded-full transition-opacity ${
                      on ? "bg-accent opacity-100" : "opacity-0"}`} />
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </header>

      <main className="flex-1 min-h-0 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1400px] px-6 py-6">
          {tab === "overview" && <OverviewTab goTo={go} />}
          {tab === "happy" && <HappyPathTab {...tabProps} />}
          {tab === "kga" && <KgaTab {...tabProps} />}
          {tab === "forward" && <ForwardSecTab {...tabProps} />}
          {tab === "spec" && <SpecDefectTab {...tabProps} />}
          {tab === "sweep" && <BatchSweepTab {...tabProps} />}
          {tab === "boundary" && <SecurityBoundaryTab {...tabProps} />}
          {tab === "pkbreak" && <PublicKeyBreakTab {...tabProps} />}
          {tab === "network" && <NetworkTab {...tabProps} />}
          {tab === "recovery" && <RecoveryTab {...tabProps} />}
          {tab === "ledger" && <LedgerTab {...tabProps} />}
          {tab === "proof" && <ProofTab goTo={go} {...tabProps} />}
        </div>
      </main>
    </div>
  );
}
