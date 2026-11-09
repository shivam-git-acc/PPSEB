"""Attack harness: the same three attacks, run against both index modes (M8).

Requirement 8.2 and Appendix A. Each function builds its own throwaway world so
the attacks cannot contaminate the live demo session, runs the attack through
the ordinary API (`SearchIndex`, `SearchNode`, `Gateway`), and returns a result
the evaluator view and `repro.json` both consume.

The point of the shared signature is the comparison: `run_attack(kind, mode)`
differs only in the mode letter. Nothing inside an attack branches on the mode
except where it must (an outsider either has the index key or does not), which is
exactly the quantity being measured.
"""

from __future__ import annotations

from dataclasses import replace

from attacks.kga import kga_attack

from .config import MedVaultConfig
from .envelope import Scope
from .service import DemoWorld, build_world
from .search import (
    IndexEntry,
    ModeAIndex,
    ModeCIndex,
    compute_token,
    paeks_keyword,
    search_signing_message,
    unpack_array,
)

#: A fixed disease dictionary so the KGA numbers are comparable between runs.
KEYWORD_DICTIONARY = (
    "diabetes", "asthma", "hypertension", "migraine", "eczema",
    "gout", "anemia", "hepatitis", "psoriasis", "thyroiditis",
)

SECRET_KEYWORD = "hypertension"

ATTACKER_MODELS = ("outsider", "keyless_server", "insider")


# --------------------------------------------------------------------------
# Sandbox construction
# --------------------------------------------------------------------------

def build_sandbox(mode: str, config: MedVaultConfig | None = None, *,
                  keywords: tuple[str, ...] = (SECRET_KEYWORD, "diabetes")) -> DemoWorld:
    """A one-record world in `mode`, granted to one doctor, ready to attack.

    Sandboxes are pinned to the in-process ledger and the signed proof mode, and
    this is deliberate: the attacks measure the gateway protocol (tokens, nonces,
    scope), and their requests carry no Groth16 proof. Inheriting a chain
    backend from the caller's session would make the harness fail for a reason
    that has nothing to do with the attack — and would cost gas per run.
    """
    base = config or MedVaultConfig(index_mode=mode)
    config = replace(base, index_mode=mode, ledger_mode="memory", zk_mode="signed")
    world = build_world(config, mode=mode)
    world.upload_record("rec-001", "patient record body", list(keywords), tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    return world


# --------------------------------------------------------------------------
# Finding 1 — offline keyword guessing
# --------------------------------------------------------------------------

def run_kga(mode: str, *, attacker: str = "outsider",
            dictionary: tuple[str, ...] = KEYWORD_DICTIONARY,
            secret_keyword: str = SECRET_KEYWORD,
            config: MedVaultConfig | None = None,
            world: DemoWorld | None = None) -> dict:
    """Run a dictionary attack against one index mode as one attacker model.

    One trial: one secret keyword, one world. `success_rate_pct` here is 0 or
    100 by construction; `kga_rate` is the function that reports a rate.

    `attacker` decides whether the attacker holds the per-doctor per-epoch index
    key:
      outsider        — no keys beyond the public material
      keyless_server  — sees the tokens, still has no key
      insider         — an authorised doctor, who does hold the key
    """
    if attacker not in ATTACKER_MODELS:
        raise ValueError(f"attacker must be one of {ATTACKER_MODELS}")
    world = world or build_sandbox(mode, config)
    doctor = world.doctors["doctor_a"]
    capability = doctor.capability
    epoch = capability.epoch if capability else 0
    seed = (config or MedVaultConfig()).sub_seed(f"kga-{mode}")

    # The captured search token: exactly what a search node (or, in the
    # baseline, every chain observer) would see for this doctor.
    request = doctor.build_request(world.index, secret_keyword, nonce=1,
                                   timestamp=world.ledger.now())
    captured_token = request.token

    if mode == "A":
        # The canonical baseline attack, from attacks/kga.py, unchanged.
        index = world.index
        assert isinstance(index, ModeAIndex)
        trap = unpack_array(captured_token, (index.params.m,))
        baseline = kga_attack(index.pk, index.mu, epoch, trap, list(dictionary),
                              index.params, seed=seed)
        recovered = baseline["recovered_keyword"]
        return {
            "mode": mode,
            "attacker": attacker,
            # Success means the RIGHT keyword; a match on another keyword is a
            # false positive, recorded separately rather than counted.
            "success": recovered == secret_keyword,
            "success_rate_pct": 100.0 if recovered == secret_keyword else 0.0,
            "wrong_keyword": recovered is not None and recovered != secret_keyword,
            # The attack encrypts the true keyword like any other guess, so a
            # miss here means the trapdoor failed Verify on an honest ciphertext
            # of its own keyword: the doctor's search would have missed too.
            "own_ciphertext_failed": recovered is None,
            "recovered_keyword": recovered,
            "guesses_tried": baseline["guesses_tried"],
            "dictionary_size": len(dictionary),
            "blocked": False,
            "method": "public PEKS.Encrypt + Verify against the captured token",
            "evidence": baseline["guesses"],
            "params": {"n": index.params.n, "q": index.params.q,
                       "sigma": index.params.sigma, "l": index.params.l},
            "trace": baseline["trace"],
        }

    if mode == "C":
        # The same public-key attack as mode A (attacks/kga.py, unchanged): the
        # trapdoor is public and Verify is public. What changes is what can be
        # encrypted. Without K_pd the attacker can only encrypt the raw guesses
        # (or guesses under a key they hold, which is not this doctor's);
        # the insider holds K_pd and authenticates each guess first.
        index = world.index
        assert isinstance(index, ModeCIndex)
        trap = unpack_array(captured_token, (index.params.m,))
        insider = attacker == "insider"
        candidates = ([paeks_keyword(capability.index_key, g) for g in dictionary]
                      if insider else list(dictionary))
        result = kga_attack(index.pk, index.mu, index.epoch, trap, candidates,
                            index.params, seed=seed)
        found = result["recovered_keyword"]
        recovered = dictionary[candidates.index(found)] if found is not None else None
        return {
            "mode": mode,
            "attacker": attacker,
            "success": recovered == secret_keyword,
            "success_rate_pct": 100.0 if recovered == secret_keyword else 0.0,
            "wrong_keyword": recovered is not None and recovered != secret_keyword,
            # Only the key holder encrypts the true keyword the way the index
            # does, so only their miss is a trapdoor failing on its own keyword.
            "own_ciphertext_failed": insider and recovered is None,
            "recovered_keyword": recovered,
            "guesses_tried": result["guesses_tried"],
            "dictionary_size": len(dictionary),
            "blocked": not insider,
            "method": ("PEKS.Encrypt on HMAC(K_pd, guess) + public Verify"
                       if insider else
                       "PEKS.Encrypt on raw guesses + public Verify, as in mode A: "
                       "without K_pd no guess matches an authenticated keyword"),
            "evidence": [{"guess": g, "match": recovered == g and found is not None}
                         for g in dictionary[: result["guesses_tried"]]],
            "params": {"n": index.params.n, "q": index.params.q,
                       "sigma": index.params.sigma, "l": index.params.l},
            "trace": result["trace"],
        }

    # mode B. An attacker without the key cannot turn a guess into a token; the
    # honest way to measure that is to let them try with a key they do have.
    if attacker == "insider":
        candidate_key = capability.index_key
        blocked = False
    else:
        # Any key the attacker could hold. It is not this doctor's, so the
        # attacker is not guessing keywords - they are guessing keys.
        candidate_key = bytes(32)
        blocked = True

    guesses = []
    recovered = None
    for guess in dictionary:
        candidate = compute_token(candidate_key, guess)
        match = candidate == captured_token
        guesses.append({"guess": guess, "match": match})
        if match:
            recovered = guess
            break

    return {
        "mode": mode,
        "attacker": attacker,
        "success": recovered == secret_keyword,
        "success_rate_pct": 100.0 if recovered == secret_keyword else 0.0,
        "wrong_keyword": recovered is not None and recovered != secret_keyword,
        "own_ciphertext_failed": False,
        "recovered_keyword": recovered,
        "guesses_tried": len(guesses),
        "dictionary_size": len(dictionary),
        "blocked": blocked,
        "method": ("HMAC-SHA-256 under the per-doctor per-epoch key"
                   if attacker == "insider" else
                   "HMAC-SHA-256 without the key: a guess cannot be turned "
                   "into a comparable token"),
        "evidence": guesses,
        "params": {"mode": "B", "key_bytes": 32},
        "trace": [],
    }


def kga_rate(mode: str, attacker: str, *, config: MedVaultConfig | None = None,
             seeds: int = 2, dictionary: tuple[str, ...] = KEYWORD_DICTIONARY) -> dict:
    """KGA success as a rate: every dictionary keyword as the secret, `seeds` worlds.

    Each seed is a fresh world (fresh PPSEB keys in mode A, fresh index keys in
    mode B). Trials = len(dictionary) × seeds. The first trial's evidence and
    trace are kept so the UI still has something concrete to show.
    """
    base = config or MedVaultConfig(index_mode=mode if mode in ("A", "B", "C") else "B")
    successes, trials, wrong, broken, first = 0, 0, 0, 0, None
    for k in range(seeds):
        world = build_sandbox(mode, replace(base, seed=base.seed + k))
        for secret in dictionary:
            trial = run_kga(mode, attacker=attacker, dictionary=dictionary,
                            secret_keyword=secret, config=base, world=world)
            successes += trial["success"]
            wrong += trial["wrong_keyword"]
            broken += trial["own_ciphertext_failed"]
            trials += 1
            first = first or trial
    working = trials - broken
    return {**first, "secret_keyword": "every dictionary keyword",
            "success": successes == trials, "successes": successes, "trials": trials,
            "seeds": seeds, "success_rate_pct": round(100.0 * successes / trials, 2),
            "wrong_keyword_matches": wrong,
            # Mode A at toy parameters: some honest trapdoors fail Verify on
            # their own keyword (deck: "the margin law"). Those trials are
            # misses for the doctor as well, so the attack is also reported
            # over the trials where search itself works.
            "own_ciphertext_failures": broken,
            "success_rate_given_working_search_pct":
                round(100.0 * successes / working, 2) if working else None}


def run_kga_unkeyed_control(*, dictionary: tuple[str, ...] = KEYWORD_DICTIONARY) -> dict:
    """Control: a "fix" that hashes the keyword without a key.

    token = SHA-256(normalise(keyword)). Anyone can hash a guess, so the
    dictionary attack succeeds on every keyword. This is why mode B's token is
    an HMAC under a per-doctor per-epoch key, not merely a hash.
    """
    from .crypto import sha256
    from .search import normalize_keyword

    successes = 0
    for secret in dictionary:
        captured = sha256(normalize_keyword(secret).encode("utf-8"))
        recovered = next((g for g in dictionary
                          if sha256(normalize_keyword(g).encode("utf-8")) == captured), None)
        successes += recovered == secret
    return {"mode": "unkeyed-hash control", "attacker": "outsider",
            "successes": successes, "trials": len(dictionary),
            "success_rate_pct": round(100.0 * successes / len(dictionary), 2),
            "method": "SHA-256(keyword) with no key: a guess is hashed and compared"}


def kga_matrix(config: MedVaultConfig | None = None, *, rates: bool = False,
               seeds: int = 2, modes: tuple[str, ...] = ("A", "B")) -> dict:
    """Every (mode, attacker) pair the evaluation table needs.

    `rates=False` (the live demo) runs one trial per cell. `rates=True`
    (repro, tests) runs `kga_rate`. In mode A the three attacker models hold
    the same material — Verify is public — so one rate is measured and reported
    for all three rather than measuring the same attack three times.
    """
    if not rates:
        single = {f"mode_{mode}": {attacker: run_kga(mode, attacker=attacker, config=config)
                                   for attacker in ATTACKER_MODELS}
                  for mode in modes}
        single["control_unkeyed_hash"] = run_kga_unkeyed_control()  # hashing only: cheap
        return single
    out: dict = {}
    if "A" in modes:
        mode_a = kga_rate("A", "outsider", config=config, seeds=seeds)
        out["mode_A"] = {attacker: {**mode_a, "attacker": attacker,
                                    "note": "same measurement for every model: Verify is public"}
                         for attacker in ATTACKER_MODELS}
    if "B" in modes:
        out["mode_B"] = {attacker: kga_rate("B", attacker, config=config, seeds=seeds)
                         for attacker in ATTACKER_MODELS}
    if "C" in modes:
        # Outsider and keyless chain node hold the same material in mode C
        # (public key, public trapdoor, public Verify, no K_pd): measured once.
        keyless = kga_rate("C", "outsider", config=config, seeds=seeds)
        out["mode_C"] = {
            "outsider": keyless,
            "keyless_server": {**keyless, "attacker": "keyless_server",
                               "note": "same material as the outsider: the trapdoor is public"},
            "insider": kga_rate("C", "insider", config=config, seeds=seeds),
        }
    out["control_unkeyed_hash"] = run_kga_unkeyed_control()
    return out


# --------------------------------------------------------------------------
# Finding 2 — universal-ciphertext planting
# --------------------------------------------------------------------------

def run_plant(mode: str, *, config: MedVaultConfig | None = None) -> dict:
    """Try to inject an entry that matches every search.

    Mode A has the strongest possible version of this attack: `CT1 = ⌊q/2⌋`,
    `CT2 = 0` matches every trapdoor, so a single planted entry turns every
    search into a hit for the attacker's record id. Mode B's write path refuses
    the entry because it carries no patient signature.

    Mode "A′" is mode A with the cheap CT2 shape check on writes
    (`medvault.wellformed`): same scheme, same open submission, same planted
    bytes; the entry is refused as `malformed_ciphertext`.
    """
    checked = mode in ("A'", "A′")
    if checked:
        base = config or MedVaultConfig(index_mode="A")
        config = replace(base, ppseb_shape_check=True)
        mode = "A"
    world = build_sandbox(mode, config)
    epoch = world.ledger.current_epoch(world.patient_id)

    # Mode C runs the same Verify as mode A, so the same forgery applies: it
    # authenticates keywords, not ciphertexts, and has no write-path checks.
    if mode in ("A", "C"):
        index = world.index
        assert isinstance(index, ModeAIndex)
        entry = index.universal_plant(epoch, "doctor_a")
        accepted, reason = world.node.add_entry(entry, None, "attacker")
        matched = world.search("doctor_a", "diabetes")[0]
        appears = "PLANTED" in matched.get("record_ids", [])
        return {
            "mode": "A′" if checked else mode,
            "accepted": accepted,
            "reason": reason,
            "planted_record_id": "PLANTED",
            "appears_in_search": appears,
            "honest_entries_indexed": len(world.node.entries("doctor_a", epoch))
                                      - (1 if accepted else 0),
            "record_ids": matched.get("record_ids", []),
            "constructed_as": "CT1 = floor(q/2), CT2 = 0 (matches every trapdoor)",
            "params": {"n": index.params.n, "q": index.params.q},
        }

    # Mode B: the attacker has no key, so they cannot even compute a token that
    # would match. They can still try to write an entry; that is the attempt.
    entry = IndexEntry(token=b"planted-token-0000000000000000000", record_id="PLANTED",
                       epoch=epoch, doctor_id="doctor_a", patient_signature=b"")
    accepted, reason = world.node.add_entry(entry, None, "attacker")
    matched = world.search("doctor_a", "diabetes")[0]
    return {
        "mode": mode,
        "accepted": accepted,
        "reason": reason,
        "planted_record_id": "PLANTED",
        "appears_in_search": "PLANTED" in matched.get("record_ids", []),
        "record_ids": matched.get("record_ids", []),
        "constructed_as": "unsigned entry written straight into the index",
        "params": {"mode": "B"},
    }


# --------------------------------------------------------------------------
# Finding 3 — replay of a captured search token
# --------------------------------------------------------------------------

def run_replay(mode: str, *, config: MedVaultConfig | None = None) -> dict:
    """Submit one valid request twice, with no changes at all.

    Mode A accepts the second submission because PPSEB has no requester
    authentication and no nonce. Mode B rejects it at the nonce gate while the
    first submission's result stands.
    """
    world = build_sandbox(mode, config)
    doctor = world.doctors["doctor_a"]
    request = doctor.build_request(world.index, "diabetes", nonce=1,
                                   timestamp=world.ledger.now())

    first, first_trace = world.submit_request(request)
    second, second_trace = world.submit_request(request)

    return {
        "mode": mode,
        "first_ok": first["ok"],
        "first_record_ids": first["record_ids"],
        "replay_ok": second["ok"],
        "replay_reason": second["reason"],
        "replay_record_ids": second["record_ids"],
        "signature_covered": search_signing_message(
            request.token, request.nonce, request.epoch, request.timestamp).hex()[:32],
        "params": {"mode": mode, "nonce": request.nonce, "epoch": request.epoch},
        "trace": second_trace,
        "first_trace": first_trace,
    }


def run_retrieval_replay(mode: str, *, config: MedVaultConfig | None = None) -> dict:
    """Deck finding 7, second half: replay a captured *retrieval* request.

    The doctor's legitimate fetch succeeds. The same request bytes are then
    submitted again by whoever captured them. Mode A hands the ciphertext over
    a second time (PPSEB authenticates nobody); mode B rejects it at the nonce
    gate. The replaying party has no DEK, so success means ciphertext and the
    access fact, never plaintext.
    """
    world = build_sandbox(mode, config)
    doctor = world.doctors["doctor_a"]
    record_id = "rec-001"
    first, _ = world.retrieve("doctor_a", record_id)
    captured = doctor.build_retrieval(record_id, doctor.next_nonce(), world.ledger.now())
    legit, _ = world.submit_retrieval(captured)
    replay, replay_trace = world.submit_retrieval(captured)
    return {
        "mode": mode,
        "first_ok": first["ok"],
        "legit_ok": legit["ok"],
        "replay_ok": replay["ok"],
        "replay_reason": replay["reason"],
        "replay_plaintext": replay.get("plaintext"),
        "replay_ciphertext_bytes": replay.get("ciphertext_bytes"),
        "params": {"mode": mode, "nonce": captured.nonce, "epoch": captured.epoch},
        "trace": replay_trace,
    }


# --------------------------------------------------------------------------
# Finding 4 — public access pattern
# --------------------------------------------------------------------------

def run_access_pattern(mode: str, *, config: MedVaultConfig | None = None) -> dict:
    """Does the observable chain log reveal the search token, or what matched?

    Modes A and C model PPSEB's on-chain search: the trapdoor and the matching
    record ids (PPSEB's step 4) are both in the public log. Mode B writes only
    SHA256(token ‖ nonce ‖ epoch). The record-id check looks for the ids the
    search actually returned — an earlier version looked for a string search
    never writes, so it could not fail.
    """
    world = build_sandbox(mode, config)
    doctor = world.doctors["doctor_a"]
    request = doctor.build_request(world.index, "diabetes", nonce=1,
                                   timestamp=world.ledger.now())
    result, _ = world.submit_request(request)
    matched = result["record_ids"]

    log = world.ledger.chain_log()
    token_hex = request.token.hex()
    leaks = any(token_hex in str(entry) for entry in log)
    search_records = [e for e in log if e.get("type") == "search_commitment_record"]
    return {
        "mode": mode,
        "token_on_chain": leaks,
        "matched_record_ids": matched,
        "record_ids_on_chain": bool(matched) and any(
            set(matched) <= set(e.get("matched", [])) for e in search_records),
        "log_entries": len(log),
        "log_keys": sorted({key for entry in log for key in entry}),
    }


# --------------------------------------------------------------------------
# Everything at once
# --------------------------------------------------------------------------

def run_all_attacks(config: MedVaultConfig | None = None, *, kga_rates: bool = False,
                    kga_seeds: int = 2, modes: tuple[str, ...] = ("A", "B")) -> dict:
    """The before/after table: every attack, every requested mode, one code path.

    The live demo uses modes A and B (PRD section 11); `repro` and the Auditor's
    "run all" add mode C. Mode A′ (A plus the shape check) only changes the
    write path, so it appears in the plant row only.
    """
    kga = kga_matrix(config, rates=kga_rates, seeds=kga_seeds, modes=modes)
    plant_modes = tuple(m for m in ("A", "A′", "B", "C")
                        if m in modes or (m == "A′" and "A" in modes))
    replay = {mode: run_replay(mode, config=config) for mode in modes}
    plant = {mode: run_plant(mode, config=config) for mode in plant_modes}
    access = {mode: run_access_pattern(mode, config=config) for mode in modes}
    retrieval = {mode: run_retrieval_replay(mode, config=config) for mode in modes}
    return {
        "kga": kga,
        "replay": replay,
        "retrieval_replay": retrieval,
        "plant": plant,
        "access_pattern": access,
        "summary": {
            "kga_outsider_pct": {mode: kga[f"mode_{mode}"]["outsider"]["success_rate_pct"]
                                  for mode in modes},
            "kga_insider_pct": {mode: kga[f"mode_{mode}"]["insider"]["success_rate_pct"]
                                 for mode in modes},
            "replay_succeeds": {mode: replay[mode]["replay_ok"] for mode in modes},
            "retrieval_replay_succeeds": {mode: retrieval[mode]["replay_ok"]
                                          for mode in modes},
            "plant_succeeds": {mode: plant[mode]["appears_in_search"]
                               for mode in plant_modes},
            "token_on_chain": {mode: access[mode]["token_on_chain"] for mode in modes},
            "record_ids_on_chain": {mode: access[mode]["record_ids_on_chain"] for mode in modes},
        },
    }
