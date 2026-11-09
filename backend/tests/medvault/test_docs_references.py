"""The security-games and design-only documents point at real tests (S4).

`docs/security-games.md` ties every game to the tests that run it. A renamed
or deleted test would silently leave a game with no evidence behind it, so
this test fails instead. It also checks the cross-document anchors.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PPSEB = Path(__file__).resolve().parents[3]
DOCS = PPSEB / "docs"
REFERENCE = re.compile(r"`(backend/tests/[\w/]+\.py)::(test_\w+)`")
LINK = re.compile(r"\]\(([\w\-]+\.md)#([\w\-]+)\)")


def _slug(heading: str) -> str:
    """GitHub-style anchor for a markdown heading."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\s\-]", "", text)
    return re.sub(r"\s", "-", text)


def _anchors(path: Path) -> set[str]:
    return {_slug(line.lstrip("#")) for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("#")}


@pytest.mark.parametrize("doc", ["security-games.md", "design-only-fixes.md"])
def test_every_cited_test_exists(doc):
    text = (DOCS / doc).read_text(encoding="utf-8")
    refs = REFERENCE.findall(text)
    if doc == "security-games.md":
        assert len(refs) >= 25, "the games document lost its test references"
    for file, name in refs:
        source = PPSEB / file
        assert source.exists(), f"{doc}: {file} does not exist"
        assert re.search(rf"^def {name}\(", source.read_text(encoding="utf-8"), re.M), \
            f"{doc}: {file}::{name} is not a test function"


@pytest.mark.parametrize("doc", ["security-games.md", "design-only-fixes.md"])
def test_cross_document_anchors_resolve(doc):
    text = (DOCS / doc).read_text(encoding="utf-8")
    for target, anchor in LINK.findall(text):
        assert anchor in _anchors(DOCS / target), f"{doc}: {target}#{anchor} has no heading"


def test_every_deck_finding_has_a_coverage_row():
    text = (DOCS / "security-games.md").read_text(encoding="utf-8")
    coverage = text[text.index("## Coverage summary"):]
    for n in range(1, 11):
        assert re.search(rf"^\| {n} · ", coverage, re.M), f"deck finding {n} has no row"
