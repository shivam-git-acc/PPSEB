import { useState } from "react";
import ParamsPanel from "./components/ParamsPanel";
import TraceTimeline from "./components/TraceTimeline";
import { ErrorBanner } from "./components/Section";
import { api } from "./api";

import OverviewTab from "./tabs/OverviewTab";
import HappyPathTab from "./tabs/HappyPathTab";
import KgaTab from "./tabs/KgaTab";
import ForwardSecTab from "./tabs/ForwardSecTab";
import SpecDefectTab from "./tabs/SpecDefectTab";
import BatchSweepTab from "./tabs/BatchSweepTab";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "happy", label: "Happy Path" },
  { id: "kga", label: "KGA Attack" },
  { id: "forward", label: "Forward Security" },
  { id: "spec", label: "Spec Defect" },
  { id: "sweep", label: "Batch Sweep" },
];

export default function App() {
  const [params, setParams] = useState({ n: 4, q: 257, sigma: 4.0, l: 10 });
  const [initialized, setInitialized] = useState(false);
  const [applying, setApplying] = useState(false);
  const [shapeTable, setShapeTable] = useState(null);
  const [maxPeriod, setMaxPeriod] = useState(0);
  const [tab, setTab] = useState("overview");
  const [trace, setTrace] = useState([]);
  const [traceTitle, setTraceTitle] = useState("Trace");
  const [initError, setInitError] = useState(null);

  const applyParams = async () => {
    setApplying(true);
    setInitError(null);
    try {
      const res = await api.init(params);
      setShapeTable(res.result.shape_table);
      setMaxPeriod(res.result.max_period);
      setInitialized(true);
      setTrace(res.trace);
      setTraceTitle("Initialization");
    } catch (e) {
      setInitError(String(e.message || e));
      setInitialized(false);
    } finally {
      setApplying(false);
    }
  };

  const handleTrace = (t, title) => {
    setTrace(t);
    setTraceTitle(title || "Trace");
  };

  const tabProps = {
    onTrace: (t) => handleTrace(t, TABS.find((x) => x.id === tab)?.label),
    initialized,
    maxPeriod,
    params,
  };

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden">
      <div className="flex flex-1 min-h-0">
        <aside className="w-[300px] shrink-0 border-r border-ink-800 hidden md:flex flex-col">
          <ParamsPanel
            params={params} setParams={setParams} onApply={applyParams}
            applying={applying} initialized={initialized} shapeTable={shapeTable}
            maxPeriod={maxPeriod}
          />
        </aside>

        <main className="flex-1 min-w-0 flex flex-col">
          <nav className="flex border-b border-ink-800 px-2 shrink-0 overflow-x-auto">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`px-4 py-3 text-sm whitespace-nowrap border-b-2 transition-colors ${
                  tab === t.id
                    ? "border-signal-blue text-ink-100"
                    : "border-transparent text-ink-400 hover:text-ink-200"
                }`}
              >
                {t.label}
              </button>
            ))}
          </nav>
          <div className="p-5 overflow-y-auto flex-1">
            <ErrorBanner message={initError} />
            {tab === "overview" && <OverviewTab goTo={setTab} />}
            {tab === "happy" && <HappyPathTab {...tabProps} />}
            {tab === "kga" && <KgaTab {...tabProps} />}
            {tab === "forward" && <ForwardSecTab {...tabProps} />}
            {tab === "spec" && <SpecDefectTab {...tabProps} />}
            {tab === "sweep" && <BatchSweepTab {...tabProps} />}
          </div>
        </main>

        <aside className="w-[400px] shrink-0 border-l border-ink-800 hidden lg:block">
          <TraceTimeline events={trace} title={traceTitle} />
        </aside>
      </div>
    </div>
  );
}
