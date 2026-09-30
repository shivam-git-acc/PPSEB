"""PATCH 18 — the Network tab's simulator: doctor / cloud / verifier / attacker.

An INCREMENTAL, mutable session (unlike attacks.end_to_end.build_frozen_history,
which builds a whole J-period history in one shot): the doctor adds records one
at a time, searches, advances the period, and decrypts; the cloud stores frozen
blobs; the verifier runs the PUBLIC Verify; and the attacker may be launched at
chosen periods with either attack.

Deviation from PATCH 18, stated up front (CLAUDE.md §10): the patch says the
stolen-key backward attack is "implemented FRESH here (not previously built)".
In this repository it WAS already built and tested -- attacks.end_to_end's
`_recover_period_candidate` (PATCH 01-06) and, on the same axis as the
public-key attack, attacks.boundary (PATCH 15). Writing a second copy would
mean a second thing to audit and two places for the R-product to be wrong, so
this module CALLS the existing, tested one. §2A's shape (assert backward-only,
R-product from public data, membership check on the result) is enforced here in
`stolen_key_attack`.

Honesty rules enforced in the data, not just on screen:
- The attacker is handed `_attacker_view(i)`, a PeriodDB whose `records` tuple
  is EMPTY: no keyword, no plaintext, no secret key can reach the attack path
  through it (PeriodDB carries no secret field at all). Scoring against the
  truth happens outside the attack, in this module.
- Level 3 (plaintext) is reported only when Decrypt with the attack-derived
  basis round-trips to the true record. The doctor's own decrypt is real and
  separate.
- The cloud's blobs are hashed when written and re-checked after every attack:
  an attack that regenerated a ciphertext would be caught, not trusted.
- A period whose attack exceeds its budget is "unmeasured (timeout)", never
  "secure". The budget is checked BETWEEN dictionary words, so a single long
  reduction can overrun it; the measured runtime is always reported.
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from attacks.end_to_end import (END_TO_END_L, TARGET_MARGIN_STD, PeriodDB, _hash_cm, _hash_ct,
                                _recover_period_candidate, verify_search)
from attacks.forward_sec import sigma_for_params, usability_threshold
from attacks.nq_sweep import h2_valid
from attacks.pk_demo import DISEASE_DICTIONARY, h2_collisions
from ppseb.hashes import H1, H1_inverse
from ppseb.linalg import (gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed, strong_reduce)
from ppseb.params import Params, default_params, derived_m
from ppseb.samplers import new_basis_del
from ppseb.scheme import decrypt_record, encrypt_record, peks_encrypt, trapdoor, verify
from ppseb.trapgen import trapgen
from ppseb.trace import Trace

N_CHOICES = (4, 8, 16)
Q_CHOICES = (257, 1153, 4001, 12289, 40961)
PAPER_DEFAULT = (4, 257)
DEFAULT_ATTACK_BUDGET_S = 120.0
DEMO_BETA = 2  # LLL-level; PATCH 14/15 measured the break at this block size

OUTCOME_RECOVERED = "recovered"
OUTCOME_FAILED = "attack failed"
OUTCOME_TIMEOUT = "unmeasured (timeout)"

GATE_CHECKS = ("kernel_ok", "match_ok", "nonmatch_ok", "search_ok", "decrypt_ok")


def _fingerprint(M: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(M).tobytes()).hexdigest()[:6]


@dataclass
class CloudRecord:
    """One frozen blob pair on the cloud. `keyword` and `text` are the GROUND
    TRUTH, held by the simulator for the vs-truth column only -- they are never
    passed into an attack (see NetworkSession._attacker_view)."""
    record_id: int
    period: int
    keyword: str
    text: str
    CT1: np.ndarray
    CT2: np.ndarray
    CM: dict

    def public_view(self) -> dict:
        """What the cloud actually reveals: sizes and a blob fingerprint."""
        return {"record_id": self.record_id, "period": self.period,
                "ct_fingerprint": _fingerprint(self.CT2),
                "cm_fingerprint": _fingerprint(self.CM["C1"]),
                "cm_bits": int(len(self.CM["C2"])), "bytes": int(self.CM["num_bytes"])}


@dataclass
class PeriodState:
    period: int
    pk: np.ndarray
    sk: np.ndarray                       # SECRET -- never leaves this module
    R_into_next: Optional[np.ndarray] = None
    records: list[CloudRecord] = field(default_factory=list)
    ct_hash: Optional[str] = None
    cm_hash: Optional[str] = None

    def ct_tuple(self) -> tuple:
        return tuple((r.record_id, r.CT1, r.CT2) for r in self.records)

    def cm_tuple(self) -> tuple:
        return tuple((r.record_id, r.CM) for r in self.records)

    def refreeze(self) -> None:
        """Re-hash after the doctor legitimately appends a record. Attacks run
        between appends and must not change these hashes."""
        self.ct_hash = _hash_ct(self.ct_tuple())
        self.cm_hash = _hash_cm(self.cm_tuple())


class NetworkSession:
    """The whole network as one object. Single-user demo state (CLAUDE.md §5)."""

    def __init__(self, n: int = PAPER_DEFAULT[0], q: int = PAPER_DEFAULT[1], seed: int = 18,
                 dictionary=DISEASE_DICTIONARY):
        self.session_id = uuid.uuid4().hex[:12]
        self.n, self.q, self.seed = n, q, seed
        self.dictionary = tuple(dictionary)
        self.trace = Trace()
        self.available = True
        self.unavailable_reason: Optional[str] = None
        self.periods: list[PeriodState] = []
        self._next_record_id = 0
        self.log: list[dict] = []

        reason = h2_valid(n, q)
        if reason:
            self.available = False
            self.unavailable_reason = f"H2 has no construction at n={n}, q={q}: {reason}"
            self.params = Params(n=n, q=q, sigma=4.0, l=10, m=0)
            self.gate = {}
            return

        base = default_params()
        self.params = Params(n=n, q=q, sigma=base.sigma, l=base.l,
                             usability_C=base.usability_C, m=0)
        self.rng = np.random.default_rng(seed)
        self.pyrng = random.Random(seed)
        self._setup()

    # -- setup ------------------------------------------------------------

    def _setup(self) -> None:
        """Key generation plus the SAME noise calibration the frozen-history
        experiments use. Without it Verify is either noiseless (and accepts any
        algebraically valid trapdoor -- the PATCH 05 audit bug) or so noisy the
        honest doctor fails; either way the demo would prove nothing."""
        p = self.params
        pk0, sk0 = trapgen(p, self.rng)
        p.sigma = sigma_for_params(sk0, p)
        sk0, _method = strong_reduce(sk0)
        self.mu = self.rng.integers(0, p.q, size=p.n).astype(np.int64)
        self.u_pke = self.rng.integers(0, p.q, size=p.n).astype(np.int64)

        p.l = END_TO_END_L
        calib = trapdoor(pk0, sk0, "__network_calibration__", 0, self.mu, p, self.pyrng)
        p.ciphertext_noise_sigma = TARGET_MARGIN_STD / float(np.linalg.norm(calib.astype(float)))

        self.periods = [PeriodState(period=0, pk=pk0, sk=sk0)]
        self.periods[0].refreeze()
        self.gate = self._correctness_gate()
        failed = [c for c in GATE_CHECKS if not self.gate.get(c)]
        if failed:
            self.available = False
            self.unavailable_reason = (
                f"the honest scheme itself is not correct at n={self.n}, q={self.q} "
                f"(failed: {', '.join(failed)}); refusing to run a broken demo")

    def _correctness_gate(self) -> dict:
        """PATCH 12/13's gate, run on a throwaway probe record so a broken
        (n, q) is reported as unavailable instead of silently misbehaving. The
        probe is discarded -- it never reaches the cloud."""
        p, st = self.params, self.periods[0]
        rng = np.random.default_rng(self.seed + 991)
        pyrng = random.Random(self.seed + 991)
        kw, other = self.dictionary[0], self.dictionary[1]
        text = b"__probe__"
        ct = peks_encrypt(st.pk, kw, 0, self.mu, p, rng, pyrng)
        ct_other = peks_encrypt(st.pk, other, 0, self.mu, p, rng, pyrng)
        cm = encrypt_record(st.pk, text, self.u_pke, p, rng, pyrng)
        trap = trapdoor(st.pk, st.sk, kw, 0, self.mu, p, pyrng)
        gate = {
            "kernel_ok": bool(np.all(mat_mod_mixed(st.pk, st.sk, p.q) == 0)),
            "match_ok": bool(verify(ct["CT1"], ct["CT2"], trap, p)[0]),
            "nonmatch_ok": not bool(verify(ct_other["CT1"], ct_other["CT2"], trap, p)[0]),
            "period_gs": gram_schmidt_norm(st.sk),
            "threshold": usability_threshold(p)["threshold"],
        }
        gate["search_ok"] = gate["match_ok"] and gate["nonmatch_ok"]
        try:
            gate["decrypt_ok"] = decrypt_record(st.pk, st.sk, cm, self.u_pke, p, pyrng) == text
        except Exception as e:  # noqa: BLE001
            gate["decrypt_ok"] = False
            gate["decrypt_error"] = f"{type(e).__name__}: {e}"
        return gate

    def _require_available(self) -> None:
        if not self.available:
            raise RuntimeError(self.unavailable_reason or "session unavailable")

    # -- doctor -----------------------------------------------------------

    @property
    def current(self) -> PeriodState:
        return self.periods[-1]

    def add_record(self, keyword: str, text: str) -> dict:
        """Doctor -> cloud: PEKS-encrypt the keyword and encrypt the record
        under the CURRENT period's public key."""
        self._require_available()
        if keyword not in self.dictionary:
            raise ValueError(f"keyword must be one of {list(self.dictionary)}")
        p, st = self.params, self.current
        rid = self._next_record_id
        self._next_record_id += 1
        ct = peks_encrypt(st.pk, keyword, st.period, self.mu, p, self.rng, self.pyrng)
        cm = encrypt_record(st.pk, text.encode(), self.u_pke, p, self.rng, self.pyrng)
        st.records.append(CloudRecord(rid, st.period, keyword, text, ct["CT1"], ct["CT2"], cm))
        st.refreeze()
        return self._event("doctor->cloud", f"Record #{rid} stored at period {st.period}",
                           {"record_id": rid, "period": st.period, "cm_bits": int(len(cm["C2"]))})

    def search(self, keyword: str) -> dict:
        """Doctor builds a trapdoor with sk_j and the VERIFIER (public, no
        secret) runs Verify over the current period's stored CT blobs."""
        self._require_available()
        p, st = self.params, self.current
        t0 = time.time()
        trap = trapdoor(st.pk, st.sk, keyword, st.period, self.mu, p, self.pyrng)
        N0 = verify_search(st.ct_tuple(), trap, p)
        truth = [r.record_id for r in st.records if r.keyword == keyword]
        return self._event(
            "doctor->verifier->doctor",
            f"Search {keyword!r} at period {st.period}: " + (f"matched record #{N0}" if N0 is not None else "no match"),
            {"keyword": keyword, "period": st.period, "N0": N0, "true_matches": truth,
             "correct": bool((N0 in truth) if truth else N0 is None),
             "trap_norm": float(np.linalg.norm(trap.astype(float))), "runtime_s": time.time() - t0,
             "verifier_used_secret": False})

    def advance_period(self) -> dict:
        """KeyExt: R = H1(pk_j, j+1) public, pk' = pk.R^-1, sk' = NewBasisDel."""
        self._require_available()
        p, st = self.params, self.current
        R = H1(st.pk, st.period + 1, p)
        R_inv = np.array([[int(x) for x in row] for row in (H1_inverse(R) % p.q)], dtype=np.int64)
        st.R_into_next = R
        pk_new = (st.pk @ R_inv) % p.q
        sk_new = new_basis_del(st.pk, R, st.sk, p.sigma, p.q, self.pyrng, R_inv=R_inv)
        sk_new, _m = strong_reduce(sk_new)
        nxt = PeriodState(period=st.period + 1, pk=pk_new, sk=sk_new)
        nxt.refreeze()
        self.periods.append(nxt)
        return self._event("doctor", f"Advanced to period {nxt.period} (KeyExt)",
                           {"period": nxt.period, "pk_fingerprint": _fingerprint(pk_new),
                            "period_gs": gram_schmidt_norm(sk_new)})

    def doctor_decrypt(self, record_id: int) -> dict:
        """The doctor's own decryption, with the TRUE secret key for the period
        that record belongs to.

        Note carried to the UI: under the scheme's own forward-security model
        the doctor DELETES sk_r|i when the period ends, so decrypting an older
        record is something a real forward-secure deployment could not do --
        it is exactly the capability the attacker is trying to reconstruct.
        The simulator keeps the old key so the demo can show the true plaintext
        beside the attacker's attempt; the note says so rather than implying
        the scheme allows it."""
        self._require_available()
        rec, st = self._find_record(record_id)
        pyrng = random.Random(int.from_bytes(
            hashlib.sha256(f"{self.seed}|{record_id}|doctor".encode()).digest()[:4], "big"))
        try:
            got = decrypt_record(st.pk, st.sk, rec.CM, self.u_pke, self.params, pyrng)
            ok = got == rec.text.encode()
            plaintext = got.decode(errors="replace")
        except Exception as e:  # noqa: BLE001
            ok, plaintext = False, f"<decrypt error: {type(e).__name__}>"
        stale = st.period != self.current.period
        return self._event(
            "cloud->doctor", f"Doctor decrypted record #{record_id}",
            {"record_id": record_id, "period": rec.period, "ok": bool(ok),
             "plaintext": plaintext if ok else None, "true_plaintext": rec.text,
             "used_key_of_period": st.period, "older_than_current": stale,
             "forward_security_note": (
                 "This used sk_r|%d, which a forward-secure deployment deletes when the period "
                 "ends. The simulator keeps it so the true plaintext can be shown next to the "
                 "attacker's attempt." % st.period) if stale else None})

    def _find_record(self, record_id: int) -> tuple[CloudRecord, PeriodState]:
        for st in self.periods:
            for r in st.records:
                if r.record_id == record_id:
                    return r, st
        raise ValueError(f"no record #{record_id} on the cloud")

    # -- attacker ---------------------------------------------------------

    def _attacker_view(self, i: int) -> PeriodDB:
        """What an attack is allowed to touch at period i: the public key, the
        stored ciphertexts, the public R. `records` is EMPTY and
        `legit_trap_demo` holds nothing -- no keyword, no plaintext, and (as
        PeriodDB has no such field at all) no secret key can arrive this way."""
        st = self.periods[i]
        return PeriodDB(period=st.period, pk_ri=st.pk, records=(), CT=st.ct_tuple(),
                        CM=st.cm_tuple(), legit_trap_demo={},
                        R_into_next=st.R_into_next if st.R_into_next is not None
                        else np.eye(self.params.m, dtype=np.int64),
                        ct_hash=st.ct_hash, cm_hash=st.cm_hash)

    def public_key_basis(self, i: int, beta: int = DEMO_BETA) -> tuple[np.ndarray, str]:
        """Attack 1's basis: built from pk_i ALONE (kernel_basis_mod_q includes
        the q*e_j vectors), then reduced. No secret of any kind is read."""
        view = self._attacker_view(i)
        return strong_reduce(kernel_basis_mod_q(view.pk_ri, self.params.q), block_size=beta)

    def stolen_key_attack(self, stolen_period: int, target_period_i: int,
                          beta: int = DEMO_BETA) -> tuple[np.ndarray, str]:
        """PATCH 18 §2A -- the backward reconstruction, delegating the actual
        R-product transform to the tested `_recover_period_candidate`.

        The attacker holds exactly one secret: sk of `stolen_period`. Every pk
        and R comes from `_attacker_view`, which carries neither secrets nor
        plaintext. Reaching FORWARD is rejected outright, and the result is
        checked to lie in L_perp_q(pk_i) before it is returned.

        The delegated transform adjoins the q*e_j vectors before reducing (see
        the sublattice-repair note in forward_sec._recover_candidate). Without
        that step the R-product's columns lie in L_perp_q(pk_i) but span a
        sublattice of index ~q^28, and the attack measures itself as far weaker
        than it is -- at n=4, q=257 the reconstructed basis came out at
        Gram-Schmidt norm ~30 instead of ~6 against an honest ~3.
        """
        if not 0 <= target_period_i < stolen_period < len(self.periods):
            raise ValueError(
                f"stolen-key attack reaches BACKWARD only: target period {target_period_i} must be "
                f"earlier than the stolen period {stolen_period} (periods 0..{len(self.periods) - 1})")
        history = [self._attacker_view(k) for k in range(len(self.periods))]
        stolen_sk = self.periods[stolen_period].sk     # the ONE secret the attacker holds
        basis, membership_ok, _trivial, _reduced, method = _recover_period_candidate(
            history, target_period_i, stolen_period, stolen_sk, self.params,
            reducer=lambda B: strong_reduce(B, block_size=beta))
        if not membership_ok:
            raise RuntimeError("reconstructed basis left L_perp_q(pk_i)")
        return basis, method

    def _label_period(self, i: int, basis: np.ndarray, budget_s: float,
                      trace: Trace | None = None) -> dict:
        """One trapdoor per dictionary word from `basis`, each searched against
        the frozen CT_i. The dictionary is public: disease names are
        low-entropy and enumerable, which is why a recovered tag means
        something."""
        view = self._attacker_view(i)
        started = time.time()
        matches: dict[int, list[str]] = {r.record_id: [] for r in self.periods[i].records}
        per_disease, timed_out = {}, False
        for disease in self.dictionary:
            if time.time() - started > budget_s:
                timed_out = True
                break
            try:
                trap = trapdoor(view.pk_ri, basis, disease, i, self.mu, self.params,
                                random.Random(self.seed + 7 + i))
            except Exception as e:  # noqa: BLE001 -- a degenerate basis simply yields no label
                per_disease[disease] = {"error": f"{type(e).__name__}: {e}", "matched": []}
                continue
            hit = [n_id for (n_id, c1, c2) in view.CT if verify(c1, c2, trap, self.params)[0]]
            per_disease[disease] = {"matched": hit}
            for n_id in hit:
                matches[n_id].append(disease)
            if trace is not None:
                trace.compute(f"Trapdoor for {disease!r} at period {i}",
                              detail=f"Matched record(s) {hit}" if hit else "Matched nothing.",
                              data={"disease": disease, "matched": hit}, algo="Network")
        return {"per_record": matches, "per_disease": per_disease, "timed_out": timed_out,
                "runtime_s": time.time() - started}

    def _score_period(self, i: int, labels: dict, basis: np.ndarray) -> dict:
        """Score the labels against the truth, then attempt Level 3 -- reported
        only when Decrypt with the ATTACK-derived basis round-trips."""
        collisions = h2_collisions(self.dictionary, i, self.params)
        colliding = {w for pair in collisions for w in pair}
        rows, recovered = [], 0
        for rec in self.periods[i].records:
            got = labels["per_record"].get(rec.record_id, [])
            exact = got == [rec.keyword]
            ambiguous = (not exact and rec.keyword in got and len(got) > 1
                         and all(w in colliding for w in got))
            plaintext, l3 = None, False
            if exact:
                recovered += 1
                try:
                    out = decrypt_record(self.periods[i].pk, basis, rec.CM, self.u_pke,
                                         self.params, random.Random(self.seed + 31 + rec.record_id))
                    l3 = out == rec.text.encode()
                    plaintext = out.decode(errors="replace") if l3 else None
                except Exception:  # noqa: BLE001
                    l3, plaintext = False, None
            rows.append({"record_id": rec.record_id, "true_disease": rec.keyword,
                         "recovered": got, "correct": exact, "collision_ambiguous": ambiguous,
                         "true_plaintext": rec.text,
                         "plaintext": plaintext, "level3": bool(l3),
                         "ciphertext_fetched": rec.public_view()["cm_fingerprint"]})
        return {"rows": rows, "recovered": recovered, "total": len(rows),
                "h2_collisions": collisions}

    def attack(self, kind: str, periods: list[int], stolen_period: Optional[int] = None,
               control: bool = False, beta: int = DEMO_BETA,
               budget_s: float = DEFAULT_ATTACK_BUDGET_S) -> dict:
        """Run `kind` in ("public_key", "stolen_key") against each ticked period.

        For a stolen-key run, the public-key-only attack is ALSO run on the same
        period, so the result can never imply the theft was necessary when it
        was not: a period is a genuine forward-security break only when the
        stolen key recovers it and the public key alone does not.
        """
        self._require_available()
        if kind not in ("public_key", "stolen_key"):
            raise ValueError("kind must be 'public_key' or 'stolen_key'")
        # Scope is validated BEFORE anything runs, so a forward-reaching request
        # is refused outright rather than surfacing as a per-period "error" row
        # that a reader might mistake for "the attack was tried and failed".
        for i in periods:
            if not 0 <= i < len(self.periods):
                raise ValueError(f"no period {i} on the cloud")
        if kind == "stolen_key":
            if stolen_period is None:
                raise ValueError("a stolen-key attack needs the period whose key was stolen")
            if not 0 <= stolen_period < len(self.periods):
                raise ValueError(f"no period {stolen_period} on the cloud")
            late = sorted(i for i in periods if i >= stolen_period)
            if late:
                raise ValueError(
                    f"stolen-key attack reaches BACKWARD only: period(s) {late} are not earlier "
                    f"than the stolen period {stolen_period}")
        trace = Trace()
        trace.threat_model(
            "Attacker holds " + ("the PUBLIC KEY only" if kind == "public_key"
                                 else f"the stolen sk_r|{stolen_period} plus public data"),
            detail="Inputs: the cloud's stored ciphertexts, the public pk/R matrices, the public "
                   "parameter mu and a disease dictionary. The attack is handed a PeriodDB with an "
                   "empty records tuple, so no keyword, plaintext or secret key can reach it."
                   + ("" if kind == "public_key" else " Earlier-period secrets are NOT available; "
                      "they are what the attack tries to reconstruct."),
            algo="Network", highlight=True)

        results = []
        for i in sorted(set(periods)):
            results.append(self._attack_one(kind, i, stolen_period, control, beta, budget_s, trace))
        self._assert_cloud_frozen()
        return {"kind": kind, "stolen_period": stolen_period, "control": control,
                "periods": results, "dictionary": list(self.dictionary),
                "conclusion": self._attack_conclusion(kind, results, control),
                "trace": trace.to_list()}

    def _attack_one(self, kind: str, i: int, stolen_period: Optional[int], control: bool,
                    beta: int, budget_s: float, trace: Trace) -> dict:
        started = time.time()
        row = {"period": i, "kind": kind, "control": control, "beta": beta,
               "budget_s": budget_s, "records": len(self.periods[i].records)}
        try:
            if control:
                # Negative control: a BKZ'd basis of an UNRELATED lattice. It
                # must recover nothing; if it recovers, the search is not
                # discriminating and NO result from this run means anything.
                rng = np.random.default_rng(self.seed + 4242 + i)
                unrelated = rng.integers(0, self.q, size=(self.n, self.params.m)).astype(np.int64)
                basis, method = strong_reduce(kernel_basis_mod_q(unrelated, self.q), block_size=beta)
            elif kind == "public_key":
                basis, method = self.public_key_basis(i, beta)
            else:
                basis, method = self.stolen_key_attack(stolen_period, i, beta)
        except Exception as e:  # noqa: BLE001
            row.update(outcome="error", error=f"{type(e).__name__}: {e}",
                       runtime_s=time.time() - started)
            return row

        row["basis_gs"] = gram_schmidt_norm(basis)
        try:
            row["honest_gs"] = gram_schmidt_norm(self.periods[i].sk)
        except Exception:  # noqa: BLE001
            # DISPLAY ONLY -- the simulator's own "how does the attack basis
            # compare to the real key" figure, never an attack input. It is
            # reported absent rather than fatal when the honest key cannot be
            # read, which is exactly what test_stolen_reads_only_stolen_sk
            # arranges by poisoning every non-stolen period's key.
            row["honest_gs"] = None
        row["reducer"] = method
        row["on_lattice"] = bool(np.all(mat_mod_mixed(self.periods[i].pk, basis, self.q) == 0))

        labels = self._label_period(i, basis, budget_s, trace)
        scored = self._score_period(i, labels, basis)
        row.update(scored)
        row["timed_out"] = labels["timed_out"]
        row["outcome"] = (OUTCOME_TIMEOUT if labels["timed_out"] and not scored["recovered"]
                          else OUTCOME_RECOVERED if scored["recovered"] else OUTCOME_FAILED)

        # The comparison strip: would the PUBLIC KEY alone have recovered this
        # period anyway? Computed, never assumed.
        if kind == "stolen_key" and not control:
            pk_basis, _m = self.public_key_basis(i, beta)
            pk_labels = self._label_period(i, pk_basis, budget_s)
            pk_scored = self._score_period(i, pk_labels, pk_basis)
            row["pk_only_recovered"] = pk_scored["recovered"]
            row["pk_only_also_recovers"] = pk_scored["recovered"] > 0
            row["forward_security_break"] = bool(scored["recovered"] > 0 and pk_scored["recovered"] == 0)
            row["comparison_note"] = (
                "genuine forward-security break: the stolen key recovered this period and the "
                "public key alone did not" if row["forward_security_break"] else
                "the public key alone would also recover this period — the stolen key added nothing"
                if row["pk_only_also_recovers"] else
                "neither the stolen key nor the public key recovered this period")
        row["runtime_s"] = time.time() - started
        trace.decision(
            f"Period {i}: {kind} attack",
            verdict=row["outcome"],
            evidence={k: row.get(k) for k in ("recovered", "total", "basis_gs", "honest_gs",
                                              "pk_only_also_recovers", "forward_security_break")},
            algo="Network", highlight=row["outcome"] == OUTCOME_RECOVERED)
        return row

    def _attack_conclusion(self, kind: str, results: list[dict], control: bool) -> str:
        rec = [r for r in results if r.get("outcome") == OUTCOME_RECOVERED]
        timed = [r for r in results if r.get("outcome") == OUTCOME_TIMEOUT]
        if control:
            return ("Negative control: a BKZ-reduced basis of an UNRELATED lattice recovered "
                    f"{sum(r.get('recovered', 0) for r in results)} tag(s) across "
                    f"{len(results)} period(s). It must be zero — if it is not, the search is not "
                    "discriminating and no recovery in this session means anything.")
        total = sum(r.get("total", 0) for r in results)
        got = sum(r.get("recovered", 0) for r in results)
        l3 = sum(1 for r in results for row in r.get("rows", []) if row.get("level3"))
        who = ("holding only the public key" if kind == "public_key"
               else "holding one stolen period key plus public data")
        parts = [f"Attacking {len(results)} period(s) {who}, the attacker recovered the disease tag "
                 f"of {got}/{total} stored records at n={self.n}, q={self.q}."]
        if l3:
            parts.append(f"The full record plaintext also decrypted for {l3} of them with the "
                         f"attack-derived basis.")
        else:
            parts.append("No record plaintext decrypted with the attack-derived basis (the record "
                         "decode bound is stricter), so only the tag was recovered.")
        if kind == "stolen_key":
            genuine = [r["period"] for r in results if r.get("forward_security_break")]
            redundant = [r["period"] for r in results if r.get("pk_only_also_recovers")]
            parts.append(
                f"Genuine forward-security break at period(s) {genuine}: the stolen key recovered "
                f"them and the public key alone did not." if genuine else
                f"The public key alone would also have recovered period(s) {redundant}, so the "
                f"theft added nothing there — 'forward security' is vacuous at these parameters."
                if redundant else "Neither key recovered anything here.")
        if timed:
            budget = timed[0].get("budget_s")
            parts.append(f"Period(s) {[r['period'] for r in timed]} exceeded the "
                         f"{budget:.0f}s budget: UNMEASURED, not secure.")
        if not rec and not timed:
            parts.append("Nothing was recovered in this run.")
        return " ".join(parts)

    def _assert_cloud_frozen(self) -> None:
        """The stored blobs an attack read must be bit-identical to the ones
        the doctor wrote -- an attack that regenerated a ciphertext with a
        recovered key would be proving nothing."""
        for st in self.periods:
            assert st.ct_hash == _hash_ct(st.ct_tuple()), f"CT at period {st.period} was mutated"
            assert st.cm_hash == _hash_cm(st.cm_tuple()), f"CM at period {st.period} was mutated"

    # -- state for the UI --------------------------------------------------

    def _event(self, edge: str, label: str, data: dict) -> dict:
        ev = {"step": len(self.log), "edge": edge, "label": label, "data": data,
              "at": time.time()}
        self.log.append(ev)
        return ev

    def state(self) -> dict:
        p = self.params
        return {
            "session_id": self.session_id, "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "n": self.n, "q": self.q, "m": p.m, "sigma": p.sigma, "l": p.l,
            "seed": self.seed, "dictionary": list(self.dictionary),
            "current_period": self.current.period if self.periods else None,
            "gate": self.gate,
            "n_choices": list(N_CHOICES), "q_choices": list(Q_CHOICES),
            "paper_default": list(PAPER_DEFAULT),
            "periods": [{"period": st.period, "pk_fingerprint": _fingerprint(st.pk),
                         "records": [r.public_view() for r in st.records],
                         "has_R": st.R_into_next is not None,
                         "ct_hash": st.ct_hash[:8] if st.ct_hash else None}
                        for st in self.periods],
            # Ground truth for the vs-truth column ONLY. Never passed to an
            # attack (see _attacker_view), and the cloud node must not show it.
            "ground_truth": {str(r.record_id): {"disease": r.keyword, "text": r.text}
                             for st in self.periods for r in st.records},
            "log": self.log[-40:],
        }


_SESSIONS: dict[str, NetworkSession] = {}


def new_session(n: int = PAPER_DEFAULT[0], q: int = PAPER_DEFAULT[1], seed: int = 18) -> NetworkSession:
    s = NetworkSession(n=n, q=q, seed=seed)
    _SESSIONS[s.session_id] = s
    return s


def get_session(session_id: str) -> NetworkSession:
    s = _SESSIONS.get(session_id)
    if s is None:
        raise KeyError(f"no such network session: {session_id}")
    return s


def parameter_options() -> dict:
    """§2B: the (n, q) pairs the selector offers, with m derived per pair and
    the ones H2 cannot support marked unavailable rather than left to break."""
    out = []
    for n in N_CHOICES:
        for q in Q_CHOICES:
            reason = h2_valid(n, q)
            out.append({"n": n, "q": q, "m": derived_m(n, q), "available": reason is None,
                        "reason": reason, "paper_default": (n, q) == PAPER_DEFAULT})
    return {"options": out, "n_choices": list(N_CHOICES), "q_choices": list(Q_CHOICES),
            "paper_default": list(PAPER_DEFAULT),
            "note": "Defaults (n=4, q=257) are the paper's demonstration parameters, where both "
                    "attacks are fast. Larger (n, q) make the attacks slower and can exceed the "
                    "per-attack budget — the Security Boundary tab characterises where."}
