"""Shared fixtures for the MedVault-PQ test suite.

Only new tests live here; the pre-existing PPSEB suite is untouched
(Requirement 8.1). Every fixture is deterministic: the project seed is 42, and
randomness inside a test is explicit.
"""

from __future__ import annotations

import pytest

from medvault.config import MedVaultConfig
from medvault.envelope import Scope
from medvault.kem import PurePythonMLKEM, get_kem_wrapper
from medvault.service import build_world

pytest_plugins = []


@pytest.fixture
def fixed_seed() -> int:
    """The documented project seed (Requirement 10.2)."""
    return 42


@pytest.fixture
def config(fixed_seed: int) -> MedVaultConfig:
    return MedVaultConfig(seed=fixed_seed)


@pytest.fixture(scope="session")
def kem():
    """One KEM wrapper for the whole session: the probe runs once."""
    return get_kem_wrapper()


@pytest.fixture(scope="session")
def pure_kem():
    """The pure-Python implementation explicitly, whatever liboqs would pick."""
    return PurePythonMLKEM()


@pytest.fixture
def world(config):
    """A world with three registered doctors and no records yet."""
    return build_world(config)


@pytest.fixture
def world_with_record(world):
    """The primary demo-scenario world: one record, two doctors with scopes."""
    world.upload_record("rec-001", "blood test: diabetes type 2",
                        ["diabetes", "blood"], tag="lab")
    world.upload_record("rec-002", "cardiology follow-up", ["cardiology"], tag="cardio")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    world.grant_scope("doctor_b", Scope.record_set(["rec-001", "rec-002"]))
    return world


@pytest.fixture
def mode_a_world(config):
    """The baseline world, used to show what the attacks do without the fixes."""
    from medvault.service import build_world as build

    world = build(config, mode="A")
    world.upload_record("rec-001", "patient record body", ["diabetes", "blood"], tag="lab")
    world.grant_scope("doctor_a", Scope.record_tag("lab"))
    return world
