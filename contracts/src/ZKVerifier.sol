// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IGroth16Verifier {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[4] calldata inputs) external view returns (bool);
}

// Classical BN254 proof verification. This wrapper has no authority to consume
// nullifiers: ConsentRegistry verifies all gates and commits state atomically.
contract ZKVerifier {
    IGroth16Verifier public immutable verifier;
    constructor(address generatedVerifier) { verifier = IGroth16Verifier(generatedVerifier); }
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[4] calldata inputs) external view returns (bool) {
        return verifier.verifyProof(a, b, c, inputs);
    }
}
