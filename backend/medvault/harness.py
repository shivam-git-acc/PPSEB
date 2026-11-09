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
    compute_token,
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
            config: MedVaultConfig | None = None) -> dict:
    """Run a dictionary attack against one index mode as one attacker model.

    `attacker` decides whether the attacker holds the per-doctor per-epoch index
    key:
      outsider        — no keys beyond the public material
      keyless_server  — sees the tokens, still has no key
      insider         — an authorised doctor, who does hold the key
    """
    if attacker not in ATTACKER_MODELS:
        raise ValueError(f"attacker must be one of {ATTACKER_MODELS}")
    world = build_sandbox(mode, config)
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
            "success": recovered is not None,
            "success_rate_pct": 100.0 if recovered is not None else 0.0,
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
        "success": recovered is not None,
        "success_rate_pct": 100.0 if recovered is not None else 0.0,
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


def kga_matrix(config: MedVaultConfig | None = None) -> dict:
    """Every (mode, attacker) pair the evaluation table needs."""
    return {
        "mode_A": {attacker: run_kga("A", attacker=attacker, config=config)
                   for attacker in ATTACKER_MODELS},
        "mode_B": {attacker: run_kga("B", attacker=attacker, config=config)
                   for attacker in ATTACKER_MODELS},
    }


# --------------------------------------------------------------------------
# Finding 2 — universal-ciphertext planting
# --------------------------------------------------------------------------

def run_plant(mode: str, *, config: MedVaultConfig | None = None) -> dict:
    """Try to inject an entry that matches every search.

    Mode A has the strongest possible version of this attack: `CT1 = ⌊q/2⌋`,
    `CT2 = 0` matches every trapdoor, so a single planted entry turns every
    search into a hit for the attacker's record id. Mode B's write path refuses
    the entry because it carries no patient signature.
    """
    world = build_sandbox(mode, config)
    epoch = world.ledger.current_epoch(world.patient_id)

    if mode == "A":
        index = world.index
        assert isinstance(index, ModeAIndex)
        entry = index.universal_plant(epoch, "doctor_a")
        accepted, reason = world.node.add_entry(entry, None, "attacker")
        matched = world.search("doctor_a", "diabetes")[0]
        appears = "PLANTED" in matched.get("record_ids", [])
        return {
            "mode": mode,
            "accepted": accepted,
            "reason": reason,
            "planted_record_id": "PLANTED",
            "appears_in_search": appears,
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


# --------------------------------------------------------------------------
# Finding 4 — public access pattern
# --------------------------------------------------------------------------

def run_access_pattern(mode: str, *, config: MedVaultConfig | None = None) -> dict:
    """Does the observable chain log reveal the search token?

    Mode A writes the token itself into the on-chain log, which is the leak.
    Mode B writes only SHA256(token ‖ nonce ‖ epoch).
    """
    world = build_sandbox(mode, config)
    doctor = world.doctors["doctor_a"]
    request = doctor.build_request(world.index, "diabetes", nonce=1,
                                   timestamp=world.ledger.now())
    world.submit_request(request)

    log = world.ledger.chain_log()
    token_hex = request.token.hex()
    leaks = any(token_hex in str(entry) for entry in log)
    return {
        "mode": mode,
        "token_on_chain": leaks,
        "log_entries": len(log),
        "log_keys": sorted({key for entry in log for key in entry}),
        "record_ids_on_chain": any("PLANTED" in str(entry) for entry in log),
    }


# --------------------------------------------------------------------------
# Everything at once
# --------------------------------------------------------------------------

def run_all_attacks(config: MedVaultConfig | None = None) -> dict:
    """The before/after table: three attacks, two modes, one code path."""
    kga = kga_matrix(config)
    replay = {mode: run_replay(mode, config=config) for mode in ("A", "B")}
    plant = {mode: run_plant(mode, config=config) for mode in ("A", "B")}
    access = {mode: run_access_pattern(mode, config=config) for mode in ("A", "B")}
    return {
        "kga": kga,
        "replay": replay,
        "plant": plant,
        "access_pattern": access,
        "summary": {
            "kga_outsider_pct": {mode: kga[f"mode_{mode}"]["outsider"]["success_rate_pct"]
                                  for mode in ("A", "B")},
            "kga_insider_pct": {mode: kga[f"mode_{mode}"]["insider"]["success_rate_pct"]
                                 for mode in ("A", "B")},
            "replay_succeeds": {mode: replay[mode]["replay_ok"] for mode in ("A", "B")},
            "plant_succeeds": {mode: plant[mode]["appears_in_search"] for mode in ("A", "B")},
            "token_on_chain": {mode: access[mode]["token_on_chain"] for mode in ("A", "B")},
        },
    }
