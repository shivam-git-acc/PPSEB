"""SHA-256 Merkle tree over a patient's records (Requirement 1.6, 1.8).

Leaf  = SHA-256(record_id ‖ content_hash)
Node  = SHA-256(left ‖ right)
Odd-width levels duplicate the last node (Bitcoin convention), so the tree is
always full and every proof has the same length for a given leaf count.

The tree itself carries no security beyond collision resistance — that is the
point. The root is the only thing that goes on-chain, and the doctor checks a
proof against it *before* touching a decryption key, so a modified or stale
blob never reaches the plaintext path.
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import sha256


@dataclass(frozen=True)
class MerkleProofStep:
    """One sibling on the path from a leaf to the root."""

    sibling: bytes
    #: "L" means the sibling sits on the left (this node is the right child).
    direction: str


@dataclass(frozen=True)
class MerkleProof:
    leaf: bytes
    steps: tuple[MerkleProofStep, ...]
    root: bytes

    def as_dict(self) -> dict:
        return {
            "leaf": self.leaf.hex(),
            "steps": [{"sibling": s.sibling.hex(), "direction": s.direction} for s in self.steps],
            "root": self.root.hex(),
        }


class MerkleTree:
    """A binary SHA-256 Merkle tree. Stateless: build, then verify."""

    @staticmethod
    def leaf_hash(record_id: str, content_hash: str | bytes) -> bytes:
        """Leaf = SHA-256(record_id_utf8 ‖ content_hash).

        `content_hash` may be hex text or raw bytes; both are accepted so the
        caller cannot accidentally hash the wrong spelling of the same value.
        """
        if isinstance(content_hash, str):
            content_hash = bytes.fromhex(content_hash)
        return sha256(record_id.encode("utf-8"), content_hash)

    @staticmethod
    def parent_hash(left: bytes, right: bytes) -> bytes:
        return sha256(left, right)

    @classmethod
    def build(cls, leaves: list[bytes]) -> tuple[bytes, list[list[MerkleProofStep]]]:
        """Build the tree; returns `(root, proofs)` with `proofs[i]` for leaf i.

        An empty leaf set yields the all-zero root: there is nothing to commit
        and nothing to prove, and a caller that later verifies against it will
        fail closed rather than succeeding vacuously.
        """
        if not leaves:
            return b"\x00" * 32, []

        proofs: list[list[MerkleProofStep]] = [[] for _ in leaves]
        # `positions[i]` is the index of leaf i in the current level.
        level = list(leaves)
        positions = list(range(len(leaves)))

        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            next_level: list[bytes] = []
            for i in range(0, len(level), 2):
                left, right = level[i], level[i + 1]
                next_level.append(cls.parent_hash(left, right))

            for leaf_index, pos in enumerate(positions):
                sibling_index = pos + 1 if pos % 2 == 0 else pos - 1
                sibling = level[sibling_index]
                direction = "L" if pos % 2 == 1 else "R"
                proofs[leaf_index].append(MerkleProofStep(sibling, direction))
                positions[leaf_index] = pos // 2

            level = next_level

        return level[0], proofs

    @staticmethod
    def verify(leaf: bytes, proof: list[MerkleProofStep], root: bytes) -> bool:
        """Walk the proof from the leaf to the root and compare."""
        current = leaf
        for step in proof:
            if step.direction == "L":
                current = MerkleTree.parent_hash(step.sibling, current)
            elif step.direction == "R":
                current = MerkleTree.parent_hash(current, step.sibling)
            else:  # an unknown direction is a malformed proof: refuse it
                return False
        return current == root

    @classmethod
    def proof_for(cls, leaves: list[bytes], index: int) -> MerkleProof:
        """Convenience: build and return the proof for one leaf."""
        if not 0 <= index < len(leaves):
            raise IndexError(f"leaf index {index} out of range for {len(leaves)} leaves")
        root, proofs = cls.build(leaves)
        return MerkleProof(leaf=leaves[index], steps=tuple(proofs[index]), root=root)
