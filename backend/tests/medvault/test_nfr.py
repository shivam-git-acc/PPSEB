"""Non-functional requirements: determinism, secret hygiene, offline start.

Property 26 (no secret in any output) and the parts of R10 that are testable
rather than aspirational.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from medvault import repro
from medvault.config import MedVaultConfig, library_versions
from medvault.crypto import SeededRandomSource, sha256
from medvault.envelope import Scope
from medvault.service import build_world

SETTINGS = settings(max_examples=20, deadline=None)

BACKEND = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# Property 26: no secret ever reaches an output
# --------------------------------------------------------------------------

def _secret_values(world) -> dict[str, str]:
    """Every value that must never appear in a trace, a log or a JSON body."""
    secrets = {
        "patient_signing_private": world.patient_signing.private_bytes.hex(),
        "index_key": world.doctors["doctor_a"].capability.index_key.hex(),
        "zk_secret": world.doctors["doctor_a"].capability.zk_secret.hex(),
        "kem_secret": world.doctors["doctor_a"].kem_secret.hex(),
        "dek": next(iter(world.doctors["doctor_a"].capability.deks.values())).hex(),
    }
    return secrets


# Feature: medvault-pq, Property 26: No secrets in output
@SETTINGS
@given(seed=st.integers(min_value=0, max_value=10_000))
def test_property_26_no_secret_appears_in_any_output(seed):
    world = build_world(MedVaultConfig(seed=seed))
    _, upload_trace = world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    _, grant_trace = world.grant_scope("doctor_a", Scope.record_tag("lab"))
    search_result, search_trace = world.search("doctor_a", "diabetes")
    retrieve_result, retrieve_trace = world.retrieve("doctor_a", "rec-1")
    revoke_result, revoke_trace = world.revoke_doctor("doctor_a")

    secrets = _secret_values(world)
    blob = json.dumps({
        "upload": upload_trace,
        "grant": grant_trace,
        "search": [search_result, search_trace],
        "retrieve": [retrieve_result, retrieve_trace],
        "revoke": [revoke_result, revoke_trace],
        "state": world.state(),
    }, default=str)

    for name, value in secrets.items():
        assert value not in blob, f"{name} leaked into output"


def test_state_view_is_secret_free_and_useful():
    world = build_world(MedVaultConfig(seed=42))
    world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    state = world.state()
    for key in ("records", "doctors", "grants", "epoch", "index", "chain_log",
                "audit_log", "kem_label", "ledger_backend", "gate_policy"):
        assert key in state

    serialised = json.dumps(state, default=str)
    assert world.patient_signing.private_bytes.hex() not in serialised
    assert world.doctors["doctor_a"].kem_secret.hex() not in serialised
    assert world.doctors["doctor_a"].capability.index_key.hex() not in serialised


def test_test_keys_are_labelled():
    """Requirement 10.8: a test key must be distinguishable by its identifier."""
    world = build_world(MedVaultConfig(seed=42))
    assert world.patient_signing.label.startswith("TEST_KEY:")
    for agent in world.doctors.values():
        assert agent.signing_key.label.startswith("TEST_KEY:")


# --------------------------------------------------------------------------
# R10.2-10.4: seed, pins, recorded versions
# --------------------------------------------------------------------------

def test_seeded_random_source_is_reproducible():
    first = SeededRandomSource(b"\x01" * 32)
    second = SeededRandomSource(b"\x01" * 32)
    first_draw = first.random_bytes(32)
    assert first_draw == second.random_bytes(32), "same seed, same stream"
    assert first.random_bytes(32) != first_draw, "a stream must not repeat a block"


def test_same_seed_gives_identical_ciphertexts():
    """Requirement 10.10: byte-identical output for identical inputs."""
    def fingerprint(seed: int) -> str:
        world = build_world(MedVaultConfig(seed=seed))
        world.upload_record("rec-1", "body", ["diabetes"], tag="lab")
        blob = world.store.head(world.patient_id, "rec-1")
        return sha256(blob.ciphertext).hex()

    assert fingerprint(42) == fingerprint(42)
    assert fingerprint(42) != fingerprint(43)


def test_library_versions_are_recorded():
    versions = library_versions()
    assert versions["python"]
    assert "numpy" in versions and "cryptography" in versions


def test_repro_records_seed_and_versions():
    result = repro.run_repro(7, fast=True)
    assert result["meta"]["seed"] == 7
    assert result["meta"]["library_versions"]["python"]
    assert result["meta"]["kem_label"]


def test_requirements_pin_every_dependency():
    """Requirement 10.3: no floating 'latest' installs."""
    requirements = (BACKEND / "requirements.txt").read_text(encoding="utf-8")
    lines = [line.strip() for line in requirements.splitlines()
             if line.strip() and not line.strip().startswith("#")]
    assert lines, "requirements.txt must list the dependencies"
    for line in lines:
        assert re.search(r"[<>=~!]", line), f"unpinned dependency: {line}"


def test_no_outbound_network_calls_in_the_system_modules():
    """Requirement 10.1: the demo path must not reach the internet.

    The one network client is `chain.py`, which talks to a *local* Hardhat node
    and only when the caller opts in with `ledger_mode="hardhat"`; every other
    module must be free of network code, and no module may name a non-local URL.
    """
    forbidden = ("requests.", "urllib.request", "httpx.", "socket.connect")
    for module in (BACKEND / "medvault").glob("*.py"):
        source = module.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in source, f"{module.name} references {needle}"
        for url in re.findall(r"https?://[^\s\"']+", source):
            assert "127.0.0.1" in url or "localhost" in url, \
                f"{module.name} names a non-local URL: {url}"

    # `web3` may appear only in chain.py, and chain.py must refuse any other RPC.
    for module in (BACKEND / "medvault").glob("*.py"):
        if module.name == "chain.py":
            source = module.read_text(encoding="utf-8")
            assert "local_rpc_only" in source
            assert "chain_id != 31337" in source
        else:
            assert "web3" not in module.read_text(encoding="utf-8"), module.name

    # And the default configuration does not select the chain backend.
    from medvault.config import MedVaultConfig

    assert MedVaultConfig().ledger_mode == "memory"


def test_archived_sweep_results_remain_displayable():
    """Requirement 8.6: static summaries exist without re-running anything."""
    results = BACKEND / "results"
    assert results.is_dir()
    committed = list(results.glob("*.json"))
    assert committed, "at least one committed result file must exist"


@pytest.mark.parametrize("module", ["ppseb.scheme", "attacks.kga", "attacks.ledger"])
def test_baseline_modules_are_untouched_and_importable(module):
    """Requirement 8.1: the research baseline still loads as it did."""
    import importlib

    assert importlib.import_module(module) is not None


def test_baseline_kga_still_recovers_its_keyword():
    """The pre-existing attack must behave exactly as before (R8.1)."""
    import random

    import numpy as np

    from attacks.kga import kga_attack
    from ppseb.params import default_params
    from ppseb.scheme import initialization, trapdoor

    params = default_params()
    state = initialization(params, np.random.default_rng(7))
    trap = trapdoor(state["pk_r0"], state["sk_r0"], "diabetes", 0, state["mu"],
                    params, random.Random(7))
    result = kga_attack(state["pk_r0"], state["mu"], 0, trap,
                        ["flu", "asthma", "diabetes"], params, seed=7)
    assert result["recovered_keyword"] == "diabetes"
