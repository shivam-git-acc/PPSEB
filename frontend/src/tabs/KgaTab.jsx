import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

const DICTIONARY = [
  "flu", "asthma", "diabetes", "hypertension", "migraine", "eczema",
  "bronchitis", "arthritis", "anemia", "gout", "insomnia", "depression",
];

export default function KgaTab({ onTrace, initialized, maxPeriod }) {
  const [secret, setSecret] = useState("diabetes");
  const [trapdoorMade, setTrapdoorMade] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [visibleGuesses, setVisibleGuesses] = useState(0);

  useEffect(() => {
    setTrapdoorMade(false);
    setResult(null);
    setVisibleGuesses(0);
  }, [secret]);

  useEffect(() => {
    if (!result) return;
    setVisibleGuesses(0);
    let i = 0;
    const total = result.guesses.length;
    const tick = () => {
      i += 1;
      setVisibleGuesses(i);
      if (i < total) setTimeout(tick, total > 8 ? 90 : 220);
    };
    const t = setTimeout(tick, 150);
    return () => clearTimeout(t);
  }, [result]);

  const makeTrapdoor = () => setTrapdoorMade(true);

  const launchAttack = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.attackKga({
        secret_keyword: secret,
        dictionary: DICTIONARY,
        period: maxPeriod,
      });
      setResult(res.result);
      onTrace(res.trace);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="Keyword-Guessing Attack" subtitle="Attacker view: only pk_rj, one captured trapdoor, and a dictionary.">
        <p className="text-sm text-ink-300 leading-relaxed">
          PPSEB claims resistance to keyword-guessing attacks, even quantum ones. But PEKS.Encrypt
          and Verify are both PUBLIC algorithms — anyone can re-run them. Pick a secret keyword the
          "doctor" will search for; the attacker below sees nothing but the public key, one
          captured trapdoor, and this dictionary.
        </p>
      </Card>

      <Card title="1. Choose the secret keyword">
        <select
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          className="mono text-sm bg-ink-900 border border-ink-700 rounded px-3 py-2"
        >
          {DICTIONARY.map((w) => <option key={w} value={w}>{w}</option>)}
        </select>
        <div className="mt-3">
          <PrimaryButton onClick={makeTrapdoor} disabled={!initialized}>
            Doctor makes trapdoor for "{secret}"
          </PrimaryButton>
        </div>
        {!initialized && <div className="text-xs text-ink-500 mt-2">Initialize params in the left rail first.</div>}
      </Card>

      {trapdoorMade && (
        <Card title="2. Trapdoor submitted to the blockchain" subtitle="threat model">
          <div className="text-xs text-signal-red bg-signal-red/10 border border-signal-red/30 rounded px-3 py-2 mb-3">
            The trapdoor is now a transaction on-chain — every consensus node (and any observer)
            can see it in the clear. No device compromise needed.
          </div>
          <PrimaryButton onClick={launchAttack} disabled={loading}>
            {loading ? "Attacking…" : "Launch attack"}
          </PrimaryButton>
          <ErrorBanner message={error} />
        </Card>
      )}

      {result && (
        <Card title="Attacker's view" subtitle="only pk_rj, mu (public), the trapdoor, and this dictionary">
          <div className="space-y-1.5">
            {result.guesses.slice(0, visibleGuesses).map((g, i) => (
              <div
                key={i}
                className={`trace-event-enter flex items-center justify-between mono text-sm px-3 py-1.5 rounded border
                  ${g.match ? "border-signal-green/50 bg-signal-green/10 flash-match" : "border-ink-800"}`}
              >
                <span>guess: <b>{g.guess}</b></span>
                <span className={g.match ? "text-signal-green font-semibold" : "text-ink-500"}>
                  {g.match ? "MATCH" : "no match"}
                </span>
              </div>
            ))}
          </div>
          {visibleGuesses >= result.guesses.length && (
            <div className="mt-4 pt-3 border-t border-ink-800">
              {result.recovered_keyword ? (
                <div className="flex items-center gap-2">
                  <Badge tone="red">BROKEN</Badge>
                  <span className="text-sm">
                    Keyword recovered: <b className="mono">{result.recovered_keyword.toUpperCase()}</b> — using only public data.
                  </span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Badge tone="neutral">not in dictionary</Badge>
                  <span className="text-sm text-ink-400">No dictionary entry matched this trapdoor.</span>
                </div>
              )}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
