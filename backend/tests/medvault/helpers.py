"""Test helpers that build small worlds quickly.

Kept out of `conftest.py` so property-based tests can call them directly —
Hypothesis refuses to keep a function-scoped fixture across generated inputs,
and the fix is to build the world in the test body, not to silence the check.
"""

from __future__ import annotations

from medvault.config import MedVaultConfig
from medvault.envelope import Scope
from medvault.service import DemoWorld, build_world


def make_sandbox(mode: str = "B", *, seed: int = 42,
                 keywords: tuple[str, ...] = ("diabetes", "blood"),
                 doctors: tuple[str, ...] = ("doctor_a",),
                 tag: str = "lab") -> DemoWorld:
    """A world with one tagged record and one grant per named doctor."""
    world = build_world(MedVaultConfig(seed=seed), mode=mode)
    world.upload_record("rec-1", "patient record body", list(keywords), tag=tag)
    for doctor_id in doctors:
        world.grant_scope(doctor_id, Scope.record_tag(tag))
    return world
