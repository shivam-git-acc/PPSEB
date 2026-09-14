"""Structured event trace — the "see everything happening on screen" contract
(CLAUDE.md §6). Every backend algorithm appends typed events to a `Trace`;
the API returns the trace list alongside the result, and the frontend renders
it as a step-by-step timeline.
"""

from __future__ import annotations

from typing import Any

import numpy as np

EVENT_TYPES = {
    "compute", "correction", "note", "threat_model", "matrix", "norm",
    "decision", "result",
}

MAX_PREVIEW_DIM = 12


def _jsonable(x: Any) -> Any:
    """Make numpy / python values JSON-safe (plain ints/floats/lists)."""
    if isinstance(x, np.ndarray):
        return _jsonable(x.tolist())
    if isinstance(x, (np.integer,)):
        return int(x)
    if isinstance(x, (np.floating,)):
        return float(x)
    if isinstance(x, list):
        return [_jsonable(v) for v in x]
    if isinstance(x, tuple):
        return [_jsonable(v) for v in x]
    if isinstance(x, dict):
        return {k: _jsonable(v) for k, v in x.items()}
    return x


def matrix_payload(M: np.ndarray, name: str = "") -> dict:
    """Shape + (possibly truncated) preview + norm of a matrix/vector, for
    embedding in a trace event's `data`. Matrices bigger than
    MAX_PREVIEW_DIM x MAX_PREVIEW_DIM are truncated (CLAUDE.md §6 rule)."""
    M = np.asarray(M)
    shape = list(M.shape)
    if M.ndim == 1:
        preview = M[:MAX_PREVIEW_DIM].tolist()
        truncated = M.shape[0] > MAX_PREVIEW_DIM
        norm = float(np.linalg.norm(M.astype(float)))
    else:
        r = min(M.shape[0], MAX_PREVIEW_DIM)
        c = min(M.shape[1], MAX_PREVIEW_DIM)
        preview = M[:r, :c].tolist()
        truncated = (M.shape[0] > MAX_PREVIEW_DIM) or (M.shape[1] > MAX_PREVIEW_DIM)
        norm = float(np.linalg.norm(M.astype(float)))
    return _jsonable({
        "name": name,
        "shape": shape,
        "preview": preview,
        "truncated": truncated,
        "frobenius_norm": norm,
    })


class Trace:
    """An ordered, appendable list of typed events for one backend operation."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(
        self,
        type: str,
        title: str,
        detail: str = "",
        data: dict | None = None,
        algo: str = "",
        highlight: bool = False,
    ) -> dict:
        assert type in EVENT_TYPES, f"unknown trace event type {type!r}"
        event = {
            "step": len(self.events) + 1,
            "type": type,
            "title": title,
            "detail": detail,
            "data": _jsonable(data or {}),
            "algo": algo,
            "highlight": highlight,
        }
        self.events.append(event)
        return event

    def compute(self, title, detail="", data=None, algo="", highlight=False):
        return self.emit("compute", title, detail, data, algo, highlight)

    def correction(self, title, paper_says, we_do, because, detail="", algo="", highlight=True):
        return self.emit(
            "correction", title, detail,
            {"paper_says": paper_says, "we_do": we_do, "because": because},
            algo, highlight,
        )

    def note(self, title, detail="", data=None, algo="", highlight=False):
        return self.emit("note", title, detail, data, algo, highlight)

    def threat_model(self, title, detail="", data=None, algo="", highlight=True):
        return self.emit("threat_model", title, detail, data, algo, highlight)

    def matrix(self, title, M, name="", detail="", algo="", highlight=False):
        return self.emit("matrix", title, detail, matrix_payload(M, name), algo, highlight)

    def norm(self, title, detail="", data=None, algo="", highlight=False):
        return self.emit("norm", title, detail, data, algo, highlight)

    def decision(self, title, verdict, evidence: dict, detail="", algo="", highlight=True):
        data = {"verdict": verdict, **evidence}
        return self.emit("decision", title, detail, data, algo, highlight)

    def result(self, title, detail="", data=None, algo="", highlight=True):
        return self.emit("result", title, detail, data, algo, highlight)

    def extend(self, other: "Trace") -> None:
        """Splice another trace's events in, renumbering steps."""
        for ev in other.events:
            ev = dict(ev)
            ev["step"] = len(self.events) + 1
            self.events.append(ev)

    def to_list(self) -> list[dict]:
        return list(self.events)
