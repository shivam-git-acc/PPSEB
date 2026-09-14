"""Finding 1 — offline keyword-guessing attack (KGA).

**Claim under test:** PPSEB claims resistance to keyword-guessing attacks,
including quantum ones (the whole point of building it on lattices).

**Reality:** PEKS.Encrypt needs only the PUBLIC key material (pk_rj, mu) to
build a searchable ciphertext for any candidate keyword, and Verify is a
PUBLIC test (no secret key involved — it only touches a ciphertext and a
trapdoor). So anyone holding one captured trapdoor and a guess dictionary can
just re-run the public encryption+verify pipeline for every guess. Lattice
hardness (LWE) and the blockchain are irrelevant to this: the vulnerability
is structural to public-key PEKS with a secret-free tester, not a weakness in
the underlying hard problem.

**Threat model:** PPSEB puts the *search* step on a blockchain — the doctor
submits their trapdoor for a query as a transaction, so every consensus node
(and hence any passive observer of the chain) sees it in the clear.
"""

from __future__ import annotations

import random

import numpy as np

from ppseb.params import Params
from ppseb.scheme import peks_encrypt, verify
from ppseb.trace import Trace


def kga_attack(
    pk_rj: np.ndarray, mu: np.ndarray, period_j: int, captured_trap: np.ndarray,
    dictionary: list[str], params: Params, seed: int = 0,
) -> dict:
    """Given only PUBLIC data (pk_rj, mu) plus one captured trapdoor and a
    dictionary of candidate keywords, recover which keyword the trapdoor was
    built for — by literally re-running the public PEKS.Encrypt + Verify
    pipeline for every guess.
    """
    trace = Trace()
    trace.threat_model(
        "Threat model: the doctor's trapdoor is a blockchain transaction",
        detail="PPSEB moves the search step on-chain for auditability: the doctor "
               "submits Trap as a transaction so a consensus node can run Verify. "
               "That means every node (and any observer of the chain) sees Trap "
               "in the clear — no compromise of the doctor's device is needed.",
        data={
            "attacker_has": ["pk_rj (public key)", "mu (public encryption parameter)",
                              "the captured trapdoor", "a keyword dictionary"],
            "attacker_lacks": ["sk_rj (the doctor's secret trapdoor basis)"],
        },
        algo="KGA",
        highlight=True,
    )
    trace.note(
        "Why this works: PEKS.Encrypt and Verify are both PUBLIC algorithms",
        detail="PEKS.Encrypt(pk_rj, guess, j) needs no secret at all (that's the "
               "point of a public-key scheme: anyone can encrypt). Verify(CT, Trap) "
               "needs no secret either. An attacker can therefore re-encrypt every "
               "dictionary word exactly as the real sender would, and test each "
               "one against the captured trapdoor exactly as the real search node would.",
        algo="KGA",
    )

    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)

    guesses = []
    found = None
    for g in dictionary:
        ct = peks_encrypt(pk_rj, g, period_j, mu, params, rng, pyrng)
        match, _y = verify(ct["CT1"], ct["CT2"], captured_trap, params)
        guesses.append({"guess": g, "match": match})
        trace.decision(
            f"Tested guess {g!r}",
            verdict="MATCH" if match else "no match",
            evidence={"guess": g, "match": match},
            algo="KGA",
        )
        if match:
            found = g
            break

    trace.result(
        f"Keyword recovered: {found!r} — using only public data" if found else
        "No dictionary entry matched the captured trapdoor",
        data={"recovered_keyword": found, "guesses_tried": len(guesses), "dictionary_size": len(dictionary)},
        algo="KGA",
        highlight=True,
    )

    return {
        "recovered_keyword": found,
        "guesses_tried": len(guesses),
        "guesses": guesses,
        "trace": trace.to_list(),
    }
