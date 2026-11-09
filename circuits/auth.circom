pragma circom 2.1.0;

// M6 — zero-knowledge authorisation (Requirement 6, design.md "M6").
//
// Statement: "I know a secret s such that Poseidon(s, scope_id, epoch_tag) is a
// leaf of the patient's current consent Merkle root, and nullifier =
// Poseidon(s, nonce)."
//
// Public : root, nullifier, scope_id, epoch_tag   (R6.2)
// Private: secret_s, pathElements, pathIndices, nonce (R6.3)
//
// Groth16 over BN254 is a *classical* proof system and the trusted setup used
// by build.js is a single-party dev ceremony: neither is suitable for real use
// (R6.14). The patient builds the tree and therefore knows every leaf secret;
// the proof hides the grant from observers and the gateway, not from the
// patient (R6.15).

include "node_modules/circomlib/circuits/poseidon.circom";

// Orders (current, sibling) by the path bit without branching.
template OrderedPair() {
    signal input current;
    signal input sibling;
    signal input sel;            // 0: current is the left child, 1: right
    signal output left;
    signal output right;

    sel * (1 - sel) === 0;       // the path bit must be a bit
    left  <== (sibling - current) * sel + current;
    right <== (current - sibling) * sel + sibling;
}

template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component order[depth];
    component hashers[depth];
    signal levels[depth + 1];
    levels[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        order[i] = OrderedPair();
        order[i].current <== levels[i];
        order[i].sibling <== pathElements[i];
        order[i].sel <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== order[i].left;
        hashers[i].inputs[1] <== order[i].right;
        levels[i + 1] <== hashers[i].out;
    }
    root <== levels[depth];
}

template AuthProof(depth) {
    // Public inputs, in this order (snarkjs publicSignals order).
    signal input root;
    signal input nullifier;
    signal input scope_id;
    signal input epoch_tag;

    // Private inputs.
    signal input secret_s;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input nonce;

    // 1. leaf = Poseidon(secret_s, scope_id, epoch_tag)
    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== secret_s;
    leafHash.inputs[1] <== scope_id;
    leafHash.inputs[2] <== epoch_tag;

    // 2. leaf is under the public root
    component merkle = MerkleInclusion(depth);
    merkle.leaf <== leafHash.out;
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }
    root === merkle.root;

    // 3. nullifier = Poseidon(secret_s, nonce)
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== secret_s;
    nullHash.inputs[1] <== nonce;
    nullifier === nullHash.out;

    // epoch_tag is bound to the membership leaf, not an unconstrained output.
}

// Depth 4 = 16 consent leaves: enough for the demo's doctors (M6-T1 asks for
// the smallest viable depth). Must match medvault/zk.py DEPTH.
component main {public [root, nullifier, scope_id, epoch_tag]} = AuthProof(4);
