import { useState } from "react";
import { api } from "../../api";
import {
  Card, Badge, Stat, PrimaryButton, SecondaryButton, ErrorBanner, Field, inputCls,
} from "../../components/Section";
import TraceTimeline from "../../components/TraceTimeline";
import { useOp } from "../../components/medvault/shared";

function StepCard({ step }) {
  const [open, setOpen] = useState(step.index === 4 || step.index === 9);
  const tone = step.pending ? "amber" : step.ok ? "green" : "red";
  const label = step.pending ? "pending" : step.ok ? "pass" : "fail";
  return (
    <div className="rounded-lg ring-1 ring-inset ring-ink-800 bg-white/[0.02]">
      <button type="button" onClick={() => setOpen((o) => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left" aria-expanded={open}>
        <span className="mono text-2xs text-ink-600 mt-0.5">{step.index}</span>
        <span className="flex-1">
          <span className="text-[13px] text-ink-200">{step.title}</span>
          {step.pending && <span className="block text-2xs text-ink-500 mt-0.5">{step.pending}</span>}
        </span>
        <Badge tone={tone}>{label}</Badge>
      </button>
      {open && step.trace?.length > 0 && (
        <div className="px-4 pb-4 border-t border-ink-800/70 pt-3">
          <TraceTimeline trace={step.trace} title={`Step ${step.index} trace`} />
        </div>
      )}
      {open && step.result && Object.keys(step.result).length > 0 && (
        <div className="px-4 pb-4">
          <pre className="mono text-2xs text-ink-400 whitespace-pre-wrap break-all max-h-56 overflow-auto">
            {JSON.stringify(step.result, null, 1).slice(0, 4000)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function DemoTab() {
  const [seed, setSeed] = useState(42);
  const [mode, setMode] = useState("B");
  const [zkMode, setZkMode] = useState("auto");
  const [ledgerMode, setLedgerMode] = useState("memory");
  const [report, setReport] = useState(null);
  const op = useOp();

  const newSession = async () => {
    setReport(null);
    await op.run(() => api.mvSession({
      seed: Number(seed), mode, zk_mode: zkMode, ledger_mode: ledgerMode,
    }));
  };

  const runDemo = async () => {
    const result = await op.run(() => api.mvDemo(Number(seed)));
    if (result) setReport(result);
  };

  const replaySaved = async () => {
    const result = await op.run(() => api.mvDemoTrace());
    if (result) setReport(result);
  };

  return (
    <div className="space-y-4">
      <Card
        title="Continuous demo — nine steps, one call"
        subtitle="One patient, three doctors, baseline attacks, the hardened path, revocation, a tampered record, and the lattice key tree. Nothing is typed in by hand."
        actions={
          <>
            <SecondaryButton onClick={replaySaved} disabled={op.busy}>
              Replay saved trace
            </SecondaryButton>
            <PrimaryButton onClick={runDemo} disabled={op.busy}>
              {op.busy ? "Running…" : "Run the demo"}
            </PrimaryButton>
          </>
        }
      >
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 items-end">
          <Field label="Seed"><input type="number" className={inputCls} value={seed} onChange={(e) => setSeed(e.target.value)} /></Field>
          <div className="col-span-1 lg:col-span-4 text-2xs text-ink-400 leading-relaxed">
            Fixed setup for every run: <span className="mono">index mode B</span>,{" "}
            <span className="mono">in-process ledger</span>, Groth16 when the prover is installed
            (otherwise the labelled signed fallback). The settings in the session panel below do
            not change the demo, and the demo does not change your session.
          </div>
        </div>
        <ErrorBanner message={op.error} />
      </Card>

      <Card
        title="Session for the Patient, Doctor and Auditor views"
        subtitle="These settings apply only to a new session. To show the blockchain, choose the local Hardhat chain here, start a session, then grant, search and revoke in the Patient and Doctor views."
      >
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 items-end">
          <Field label="Seed"><input type="number" className={inputCls} value={seed} onChange={(e) => setSeed(e.target.value)} /></Field>
          <Field label="Index mode">
            <select className={inputCls} value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="B">B — hardened</option>
              <option value="A">A — PPSEB baseline</option>
              <option value="C">C — PAEKS-style PPSEB</option>
            </select>
          </Field>
          <Field label="Proof mode">
            <select className={inputCls} value={zkMode} onChange={(e) => setZkMode(e.target.value)}>
              <option value="auto">auto (Groth16 when built)</option>
              <option value="groth16">groth16</option>
              <option value="signed">signed fallback</option>
            </select>
          </Field>
          <Field label="Ledger">
            <select className={inputCls} value={ledgerMode} onChange={(e) => setLedgerMode(e.target.value)}>
              <option value="memory">in-process</option>
              <option value="hardhat">local Hardhat chain</option>
            </select>
          </Field>
          <PrimaryButton onClick={newSession} disabled={op.busy}>New session</PrimaryButton>
        </div>
        <p className="text-2xs text-ink-500 mt-3 leading-relaxed">
          A new session replaces the world every MedVault view reads from. The Hardhat chain needs
          <span className="mono"> start.cmd --with-chain</span> running first.
        </p>
      </Card>

      {report?.replayed && (
        <div className="text-2xs text-signal-amber bg-signal-amber/10 ring-1 ring-inset ring-signal-amber/30 rounded-lg px-3 py-2">
          Replayed from a saved JSON trace — these events were recorded by an earlier run and
          were not re-executed now. Source: <span className="mono">{report.replayed_from}</span>
          {report.replayed_source === "bundled" && (
            <span className="block mt-1">
              The backend could not be reached (<span className="mono">{report.backend_error}</span>),
              so this is the golden run bundled with the UI.
            </span>
          )}
        </div>
      )}

      {report?.trace_saved && (
        <div className="text-2xs text-ink-400 rounded-lg ring-1 ring-inset ring-ink-800 px-3 py-2">
          Saved as the latest run.{" "}
          {report.trace_saved.promoted
            ? "It also replaced the golden replay trace"
            : "The golden replay trace was kept"}{" "}
          ({report.trace_saved.reason}).
        </div>
      )}

      {report && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
            <Stat label="Graded steps" value={`${report.passed}/${report.graded}`} tone={report.all_passed ? "ok" : "break"} />
            <Stat label="Pending" value={report.pending.length ? report.pending.join(", ") : "none"} />
            <Stat label="Elapsed" value={`${report.elapsed_s}s`} hint="budget 600 s" />
            <Stat label="Proof" value={report.proof_mode.includes("Groth16") ? "Groth16" : "signed"} hint={report.proof_mode} />
            <Stat label="Ledger" value={report.ledger_backend} />
          </div>

          <Card title="Steps" subtitle="Open a step for its result and its ordered trace.">
            <div className="space-y-2">
              {report.steps.map((step) => <StepCard key={step.index} step={step} />)}
            </div>
          </Card>

          <Card title="Claims this run supports" subtitle="Taken from the response, not from this page.">
            <ul className="text-[13px] text-ink-300 space-y-1">
              <li>· every finding has a named fix and a regression test node;</li>
              <li>· cost and leakage are measured, not estimated;</li>
              <li>· key wrapping (ML-KEM-768) and PIR (LWE, n=1024, q=2^32) use lattice assumptions;</li>
              <li>· KGA/plant/replay outcomes and all sizes reproduce for a given seed.</li>
            </ul>
            <p className="text-2xs text-ink-500 mt-3 leading-relaxed">
              Not claimed: "post-quantum system", "PPSEB is Module-LWE", "forward security proven",
              "revocation recalls downloaded data", "LWE is broken", "production-ready". The Groth16
              setup is a single-party dev ceremony and the PIR prototype is in-process.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}
