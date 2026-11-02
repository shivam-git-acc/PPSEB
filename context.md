# Context of "PPSEB: A Postquantum Public-Key Searchable Encryption Scheme on Blockchain for E-Healthcare Scenarios"

## Why was this paper made?
In modern E-healthcare scenarios, massive amounts of medical data are generated and outsourced to Electronic Health Record (EHR) systems in the cloud. However, this outsourcing introduces significant privacy risks since the third-party cloud servers cannot be fully trusted. To address this, Public Key Encryption with Keyword Search (PEKS) schemes have been used, but they face severe modern challenges:
1. They are vulnerable to Keyword Guessing Attacks (KGA) from quantum computers.
2. They incur huge computational overhead on cloud servers.
3. They suffer from key exposure problems, lacking forward privacy (if a doctor's current key is stolen, past medical records can be compromised).
4. They rely on an untrusted third party for the search process, which could provide unreliable or compromised results.

## What problem it solves?
The paper solves the problem of securely sharing and searching encrypted medical data in cloud-assisted EHR systems without relying on a trusted centralized third party, while also ensuring the system is secure against future quantum computer attacks and protects against the leakage of historical data if a secret key is compromised.

## How it solves the problem?
The authors propose **PPSEB** (Postquantum Public-key Searchable Encryption scheme on Blockchain). It solves the identified problems through two main mechanisms:
1. **Lattice-Based Cryptography:** It uses the Learning With Errors (LWE) hardness assumption to construct a post-quantum cryptographic scheme. This ensures resistance against quantum computing KGA and achieves **forward security** by associating keys with specific time periods, meaning a leaked key in the present does not compromise data from the past.
2. **Blockchain Technology:** It replaces the traditional centralized third-party search server with a decentralized blockchain network. Smart contracts are used to execute the search process, ensuring that the search is transparent, traceable, and cannot be tampered with by a malicious cloud provider.

## What promises were made?
The authors made the following promises/contributions:
- To propose a post-quantum secure PEKS scheme (PPSEB) tailored for E-healthcare scenarios.
- To introduce blockchain to decentralize the search oracle and enhance system security by removing third-party reliance.
- To achieve forward security to mitigate the damages of secret key leakage.
- To provide computational proofs of correctness and provable security, and to demonstrate through comprehensive performance evaluations that PPSEB is more computationally efficient and suitable for medical scenarios than existing outperforming schemes.

## How is the architecture?
The architecture consists of four main entities:
1. **Patient (Data Owner):** Encrypts their EHR data and uploads it to a Cloud Server. Generates keywords and sequence numbers, and adds blocks to the blockchain.
2. **Doctor (Data User):** Generates a cryptographic "trapdoor" for a specific keyword they want to search for, and submits this trapdoor to the blockchain.
3. **Blockchain Network:** Receives the trapdoor and uses a smart contract (chaincode) to search for the corresponding sequence number, then submits the retrieval request to the Cloud Server.
4. **Cloud Server:** Stores the heavily encrypted EHR data. Uses the trapdoor forwarded by the blockchain to locate the exact encrypted data matching the keyword and returns it to the doctor, without ever learning the plaintext data or the keyword itself.

## What security analysis states?
- **Correctness:** The analysis proves mathematically that as long as the noise vectors in the LWE scheme are kept below a certain threshold, the decryption and search processes will not produce errors, ensuring the doctor always gets the correct records.
- **Provable Security:** The scheme's security is reduced to the hardness of the Learning With Errors (LWE) problem under the random oracle model. The analysis proves that an attacker's advantage in breaking the indistinguishability of the ciphertexts is negligible, demonstrating strong resistance against quantum attacks and confirming forward security.

## Did the problem get solved?
Yes, within the scope of the paper's theoretical models and simulations. The performance evaluations (simulated in C++) show that PPSEB successfully provides post-quantum security and forward secrecy while actually reducing the size of the trapdoors and maintaining a very low computational testing time compared to previous PEKS schemes (like those by Boneh et al. and Ma et al.).

## Possible gaps in the paper
1. **Blockchain Overhead:** While the paper mentions efficiency, blockchains inherently introduce high latency (due to consensus mechanisms) and storage overhead. The real-time viability of waiting for a smart contract consensus during an emergency medical data retrieval is not fully addressed.
2. **Search Functionality Limits:** The paper focuses on exact, single-keyword searches. In real medical scenarios, doctors often need fuzzy keyword searches, multi-keyword conjunctives, or semantic searches, which are much harder to implement efficiently using lattice-based cryptography.
3. **Patient Computation Burden:** Lattice-based encryption can be computationally heavy and requires larger key sizes. The paper assumes patients (potentially using mobile devices) can handle the encryption, keyword extraction, and blockchain interaction seamlessly.
4. **Key Revocation/Management:** The practical difficulties of managing and updating period-based keys across many disparate healthcare providers and patients are understated.

## Is the paper applicable for real life scenarios? If not, why?
The paper presents a very strong theoretical foundation, but it is **not immediately applicable** to real-life healthcare scenarios today for several reasons:
- **Regulatory and Compliance Issues:** Blockchain's immutable nature clashes with data privacy regulations like GDPR (the "Right to be Forgotten"). If a patient's encrypted keyword index is permanently on a blockchain, deleting their record completely becomes problematic.
- **Infrastructure Readiness:** There is currently no unified, globally or nationally adopted blockchain network among hospitals that can handle the massive throughput required for EHR searches at scale.
- **Complexity and Integration:** Integrating post-quantum lattice cryptography and blockchain smart contracts into legacy hospital IT systems would require a massive overhaul of existing databases and communication protocols. 
- **Storage/Bandwidth Constraints:** Although optimized, post-quantum cryptography generally results in much larger ciphertext and key sizes than currently used classical cryptography (like RSA/ECC), which would heavily strain the storage and bandwidth of existing medical networks.
