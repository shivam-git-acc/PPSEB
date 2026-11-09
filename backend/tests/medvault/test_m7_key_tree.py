"""R7 / Properties 23-24: the lattice epoch key tree (M7).

Toy parameters, stated as such: `KeyTreeConfig` defaults to n=2, q=257. The
tests assert structure, correctness, erasure behaviour, and measured norms —
never a forward-security claim (design.md, M7).

Every test builds its own tree: `advance_epoch` mutates and erases, so sharing
one instance across tests would make the result depend on test order.
"""

from __future__ import annotations

import json

import pytest

from medvault.key_tree import KeyTree, KeyTreeConfig

DEPTH = 3


def make_tree(seed: int = 42, depth: int = DEPTH) -> KeyTree:
    return KeyTree(KeyTreeConfig(depth=depth, seed=seed)).build()


def test_every_node_satisfies_a_times_t_mod_q():
    """Property 23: a delegated child still solves A*T = 0 mod q."""
    tree = make_tree()
    correctness = tree.check_all_correctness()
    assert set(correctness) == set(tree.nodes)
    assert all(correctness.values()), {i: ok for i, ok in correctness.items() if not ok}


def test_tree_has_every_level_and_the_right_number_of_leaves():
    tree = make_tree()
    assert len(tree.nodes) == 2 ** (tree.config.depth + 1) - 1
    assert [sum(1 for n in tree.nodes.values() if n.level == level)
            for level in range(tree.config.depth + 1)] == [1, 2, 4, 8]


def test_norms_are_measured_per_level_and_stay_usable():
    """Property 24: delegation cost is reported, not hidden."""
    tree = make_tree()
    rows = tree.norm_summary()
    assert [r["level"] for r in rows] == list(range(tree.config.depth + 1))
    for row in rows:
        assert row["min_norm"] <= row["mean_norm"] <= row["max_norm"]
        assert row["usable"] is True, row
    assert all(row["threshold"] > 0 for row in rows)


def test_bad_parameters_are_rejected():
    with pytest.raises(ValueError):
        KeyTreeConfig(depth=0)
    with pytest.raises(ValueError):
        KeyTreeConfig(depth=6)


def test_frontier_covers_the_remaining_epochs():
    tree = make_tree()
    for epoch in range(tree.num_epochs):
        tree.advance_epoch(epoch)
        retained = tree.frontier
        for leaf in (n.node_id for n in tree.nodes.values() if n.is_leaf and n.epoch >= epoch):
            node = leaf
            while node >= 1:
                if node in retained:
                    break
                node //= 2
            else:
                pytest.fail(f"leaf {leaf} has no retained ancestor at epoch {epoch}")


def test_past_epoch_secrets_are_erased_and_reachable_ones_are_not():
    tree = make_tree()
    tree.advance_epoch(4)
    with pytest.raises(ValueError, match="erased_key"):
        tree.get_leaf_key(3)
    pk, sk = tree.get_leaf_key(4)
    # Public key is n x m, the trapdoor basis is m x m, and A*T = 0 still holds.
    assert pk.shape == (tree.config.params.n, sk.shape[0])
    assert tree.nodes[tree.num_epochs + 4].correct is True
    assert sum(n.sk is not None for n in tree.nodes.values()) == len(tree.frontier)


def test_advancing_backwards_is_refused():
    tree = make_tree()
    tree.advance_epoch(5)
    with pytest.raises(ValueError):
        tree.advance_epoch(4)
    with pytest.raises(ValueError):
        tree.advance_epoch(tree.num_epochs)


def test_peks_matches_within_an_epoch_and_never_across_epochs():
    tree = make_tree(seed=7, depth=2)
    rows = tree.measure_peks()
    assert len(rows) == tree.num_epochs
    assert all(row["same_epoch_match"] for row in rows)
    assert not any(row["cross_epoch_match"] for row in rows)


def test_public_view_contains_no_secret_material():
    tree = make_tree()
    view = json.dumps(tree.public_view())
    assert "No forward-security claim" in view
    assert all(set(node) == {"node_id", "level", "epoch", "retained", "correct", "norm"}
               for node in tree.public_view()["nodes"])
    for node in tree.nodes.values():
        if node.sk is not None:
            assert str(node.sk.tolist()) not in view


def test_norm_plot_is_written(tmp_path):
    path = make_tree().plot_norms(tmp_path / "norms.png")
    assert path.exists() and path.stat().st_size > 0
