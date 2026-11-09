"""M7 research arm: real TrapGen/NewBasisDel tree, frontier erasure, measured norms.

This toy-parameter experiment demonstrates structure and correctness, not forward
security. Python erasure drops/zeroes owned arrays; it cannot erase copied keys.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field, asdict
from pathlib import Path

import numpy as np
from ppseb.params import Params
from ppseb.trapgen import trapgen
from ppseb.samplers import new_basis_del
from ppseb.hashes import H1, H1_inverse
from ppseb.linalg import gram_schmidt_norm, mat_mod_mixed
from ppseb.scheme import peks_encrypt, trapdoor, verify
from ppseb.trace import Trace
from attacks.forward_sec import usability_threshold


@dataclass
class KeyTreeConfig:
    depth: int = 4
    params: Params = field(default_factory=lambda: Params(n=2, q=257, sigma=4, l=10))
    seed: int = 42

    def __post_init__(self):
        if not 1 <= self.depth <= 5:
            raise ValueError('depth must be 1..5 (demo default 4, stretch 5)')
        if self.params.validate():
            raise ValueError('; '.join(self.params.validate()))


@dataclass
class TreeNode:
    node_id: int
    epoch: int
    level: int
    pk: np.ndarray
    sk: np.ndarray | None = field(repr=False)
    is_leaf: bool = False
    children: list[int] = field(default_factory=list)
    retained: bool = False
    norm: float = 0.0
    correct: bool = False


class KeyTree:
    def __init__(self, config: KeyTreeConfig | None = None):
        self.config = config or KeyTreeConfig()
        self.num_epochs = 2 ** self.config.depth
        self.nodes: dict[int, TreeNode] = {}
        self.frontier: set[int] = set()
        self.norms_per_level: dict[int, list[float]] = {}
        self.current_epoch = -1
        self.trace = Trace()
        self._rng = random.Random(self.config.seed)
        self.mu = np.random.default_rng(self.config.seed + 1).integers(
            0, self.config.params.q, size=self.config.params.n, dtype=np.int64)

    def _record(self, node: TreeNode):
        node.correct = self.check_correctness(node)
        if not node.correct:
            raise ValueError(f'key_tree_invalid: node {node.node_id} failed A*T mod q')
        node.norm = gram_schmidt_norm(node.sk)
        self.nodes[node.node_id] = node
        self.norms_per_level.setdefault(node.level, []).append(node.norm)
        self.trace.norm(f'Node {node.node_id} at level {node.level}',
                        data={'node_id': node.node_id, 'level': node.level,
                              'gram_schmidt_norm': node.norm, 'correct': node.correct}, algo='KeyTree')

    def _derive(self, parent: TreeNode, child_id: int) -> TreeNode:
        if parent.sk is None:
            raise ValueError('erased_key: cannot delegate from this node')
        params = self.config.params
        R = H1(parent.pk, child_id, params)
        inverse = np.asarray(H1_inverse(R) % params.q, dtype=np.int64)
        pk = parent.pk @ inverse % params.q
        sk = new_basis_del(parent.pk, R, parent.sk, params.sigma, params.q,
                           self._rng, R_inv=inverse)
        level = parent.level + 1
        node = TreeNode(child_id, child_id - self.num_epochs if level == self.config.depth else -1,
                        level, pk, sk, level == self.config.depth)
        self._record(node)
        if child_id not in parent.children:
            parent.children.append(child_id)
        return node

    def build(self, rng=None):
        if self.nodes:
            raise ValueError('tree already built')
        params = self.config.params
        pk, sk = trapgen(params, rng or np.random.default_rng(self.config.seed))
        self._record(TreeNode(1, -1, 0, pk, sk))
        for level in range(self.config.depth):
            for parent_id in range(2 ** level, 2 ** (level + 1)):
                parent = self.nodes[parent_id]
                self._derive(parent, 2 * parent_id)
                self._derive(parent, 2 * parent_id + 1)
        self.frontier = {1}
        return self

    def check_correctness(self, node: TreeNode) -> bool:
        if node.sk is None:
            return node.correct  # historical check; no retained secret to check again
        return bool(np.all(mat_mod_mixed(node.pk, node.sk, self.config.params.q) == 0))

    def check_all_correctness(self) -> dict[int, bool]:
        return {i: self.check_correctness(node) for i, node in self.nodes.items()}

    def _cover(self, node: int, left: int, right: int, first: int) -> set[int]:
        if right <= first:
            return set()
        if left >= first:
            return {node}
        mid = (left + right) // 2
        return self._cover(node * 2, left, mid, first) | self._cover(node * 2 + 1, mid, right, first)

    def _materialize(self, target: int):
        node = self.nodes[target]
        if node.sk is not None:
            return
        parent = target // 2
        if not parent:
            raise ValueError('erased_key: no ancestor retained')
        self._materialize(parent)
        self._derive(self.nodes[parent], target)

    def advance_epoch(self, target_epoch: int, rng=None):
        if target_epoch < self.current_epoch or not 0 <= target_epoch < self.num_epochs:
            raise ValueError('cannot move backward or outside the epoch range')
        if rng is not None:
            self._rng = rng
        retained = self._cover(1, 0, self.num_epochs, target_epoch + 1)
        retained.add(self.num_epochs + target_epoch)
        for node_id in sorted(retained):
            self._materialize(node_id)
        for node_id, node in self.nodes.items():
            node.retained = node_id in retained
            if not node.retained and node.sk is not None:
                node.sk.fill(0)
                node.sk = None
        self.frontier = retained
        self.current_epoch = target_epoch
        self.trace.note('Frontier advanced; non-frontier owned secret arrays erased',
                        data={'epoch': target_epoch, 'frontier': sorted(retained),
                              'retained_secret_count': len(retained)}, algo='KeyTree')

    def get_leaf_key(self, epoch: int):
        node_id = self.num_epochs + epoch
        if node_id not in self.frontier or self.nodes[node_id].sk is None:
            raise ValueError('erased_key: epoch leaf is not on frontier')
        return self.nodes[node_id].pk, self.nodes[node_id].sk

    def measure_peks(self, keyword='hypertension') -> list[dict]:
        """Full-tree experiment before erasure; report actual failures, never force match."""
        params = self.config.params
        rows = []
        for epoch in range(self.num_epochs):
            node = self.nodes[self.num_epochs + epoch]
            if node.sk is None:
                raise ValueError('measure PEKS before epoch erasure')
            rng = np.random.default_rng(self.config.seed + epoch + 100)
            py_rng = random.Random(self.config.seed + epoch + 100)
            ct = peks_encrypt(node.pk, keyword, epoch, self.mu, params, rng, py_rng)
            token = trapdoor(node.pk, node.sk, keyword, epoch, self.mu, params, py_rng)
            same, _ = verify(ct['CT1'], ct['CT2'], token, params)
            other = (epoch + 1) % self.num_epochs
            other_node = self.nodes[self.num_epochs + other]
            foreign_token = trapdoor(other_node.pk, other_node.sk, keyword, other,
                                     self.mu, params, py_rng)
            cross, _ = verify(ct['CT1'], ct['CT2'], foreign_token, params)
            rows.append({'epoch': epoch, 'same_epoch_match': same, 'cross_epoch_match': cross})
        return rows

    def norm_summary(self) -> list[dict]:
        threshold = usability_threshold(self.config.params)
        # Existing helper returns the full model, not only a scalar.
        threshold_value = threshold['threshold'] if isinstance(threshold, dict) else threshold
        return [{'level': level, 'count': len(values), 'min_norm': min(values),
                 'mean_norm': float(np.mean(values)), 'max_norm': max(values),
                 'threshold': threshold_value, 'usable': max(values) <= threshold_value}
                for level, values in sorted(self.norms_per_level.items())]

    def public_view(self):
        return {'depth': self.config.depth, 'epochs': self.num_epochs,
                'params': asdict(self.config.params), 'seed': self.config.seed,
                'correctness': self.check_all_correctness(), 'norms': self.norm_summary(),
                'frontier': sorted(self.frontier), 'current_epoch': self.current_epoch,
                'claim': 'Tree structure implemented; correctness verified; norm cost measured. No forward-security claim.',
                'nodes': [{'node_id': n.node_id, 'level': n.level, 'epoch': n.epoch,
                           'retained': n.retained, 'correct': n.correct, 'norm': n.norm}
                          for n in self.nodes.values()]}

    def plot_norms(self, filename: Path):
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        rows = self.norm_summary()
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.plot([r['level'] for r in rows], [r['max_norm'] for r in rows], 'o-', label='Max Gram-Schmidt norm')
        ax.axhline(rows[0]['threshold'], color='red', linestyle='--', label='Toy usability threshold')
        ax.set(xlabel='Tree level', ylabel='Norm', title='Lattice epoch tree — measured, not forward-security proof')
        ax.legend()
        fig.tight_layout()
        fig.savefig(filename)
        plt.close(fig)
        return filename
