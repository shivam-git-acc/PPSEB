# Inconsistencies and Defects in the PPSEB Paper

During the implementation and analysis of the paper *"PPSEB: A Postquantum Public-Key Searchable Encryption Scheme on Blockchain for E-Healthcare Scenarios"* (Xu et al., 2022), several critical inconsistencies, specification defects, and unstated assumptions were identified. 

To create a mathematically sound and functioning implementation, our codebase had to deviate from or correct the paper's printed text in the following ways.

## 1. Specification Defect in Key Extraction (Algorithm 2)
**The Paper:** Algorithm 2 contains two impossible circular dependencies:
- **Correction A (Line 7 typo):** The algorithm uses `sk_{r||j}` as an input to `NewBasisDel` to generate `SK_{r||j}`. A function cannot take the basis it is trying to generate as its input. 
- **Correction B (Line 6 circularity):** The algorithm computes the matrix `R` using `pk_{r||j}` (the public key for the current period), which has not been generated yet.

**Our Implementation:** We corrected this to a well-defined, single-step derivation. `NewBasisDel` must take the *previous* period's basis (`sk_{r||i}`) as the source, and `R` must be computed using only the *previous* period's public key (`pk_{r||i}`).

## 2. Unstated Shared Matrix $B_j$ Assumption (PEKS.Encrypt)
**The Paper:** In Algorithm 3 (PEKS), the equations for generating the two ciphertext components $CT_{j1}$ and $CT_{j2}$ both use a random matrix denoted as $B_j$. The paper is ambiguous about whether this is two independent samplings of $B_j$ or the exact same matrix.
**Our Implementation:** We enforce that $B_j$ is **strictly shared** between both components. If independent matrices are used, the trapdoor term $Trap^T CT_{j2}$ will never cancel out the $\mu^T B_j$ term in $CT_{j1}$ during the Verification phase. Without this undocumented, load-bearing assumption, the `Verify` algorithm always rejects, even for perfectly matching keywords.

## 3. Verification Threshold Mismatch ($q/5$ vs $q/4$)
**The Paper:** In Section 5.1 (Correctness), the mathematical proof bounds the noise vector to $q/5$ to ensure that the decryption process does not make mistakes. However, in the actual pseudocode for Algorithm 5 (Verification, Line 5), the algorithm checks if the distance from $q/2$ exceeds $q/4$.
**Our Implementation:** We utilize the $q/4$ threshold as printed in Algorithm 5, which is also the standard rounding threshold for LWE decoding, noting the inconsistency with the paper's prose proof.

## 4. Unspecified Hash Function $H_1$ (Requires Low-Norm Invertibility)
**The Paper:** The paper defines $H_1$ as a hash function outputting a matrix in $\mathbb{Z}_q^{m \times m}$ but provides no concrete construction. However, for the lattice basis delegation (Lemma 5) to work, the output of $H_1$ must be both **invertible** and have a **low norm**. A standard cryptographic hash cannot guarantee this.
**Our Implementation:** We instantiate $H_1$ explicitly as $I + N$ (where $I$ is the identity matrix and $N$ is a strictly upper-triangular matrix derived from the hash seed with entries in $\{-1, 0, 1\}$). This ensures the determinant is exactly 1 (always invertible) and the norm remains small.

## 5. Unspecified Hash Function $H_2$ (Requires Full-Rank Difference)
**The Paper:** Similarly, $H_2$ is defined as mapping strings to $\mathbb{Z}_q^{m \times m}$ without a construction. The security proof implicitly requires that for any two distinct keywords $w \neq w'$, the difference $H_2(w) - H_2(w')$ is an invertible matrix.
**Our Implementation:** We implement an FRD (Full-Rank Difference) encoding approach for $H_2$. Without this, a collision in the matrix differences would break the trapdoor mechanism. 

## 6. False Claim of KGA Resistance
**The Paper:** The authors claim the PPSEB scheme resists Keyword Guessing Attacks (KGA) launched by quantum opponents.
**Our Implementation/Analysis:** The analysis proves this claim is structurally invalid. Because it is a Public-Key Encryption with Keyword Search (PEKS) scheme where the `Verify` function does not require a secret key, anyone who has the public key and a trapdoor can verify keywords. The paper proposes putting the trapdoor on a public blockchain, which exposes it to all consensus nodes. Any attacker can simply run an offline dictionary attack (encrypting medical dictionary terms with the public key and testing them against the public trapdoor) to recover the patient's keyword. The LWE hardness and blockchain integration provide zero protection against this specific attack vector.
