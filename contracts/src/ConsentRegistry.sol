// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import './ZKVerifier.sol';

contract ConsentRegistry {
    uint256 public constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    struct Doctor { bytes32 sigKeyHash; bytes32 kemKeyHash; bool registered; }
    struct Grant { bytes32 scopeHash; uint64 expiresAt; uint64 epoch; bool active; }
    struct RecordRoot { bytes32 root; uint64 version; }
    mapping(address => Doctor) public doctors;
    mapping(address => mapping(address => Grant)) public grants;
    mapping(address => uint64) public epochs;
    mapping(address => RecordRoot) public recordRoots;
    mapping(address => bytes32) public consentRoots;
    mapping(address => mapping(address => uint256)) public lastNonces;
    mapping(uint256 => bool) public nullifiers;
    ZKVerifier public immutable zkVerifier;
    bool public immutable requireProof;

    event DoctorRegistered(address indexed doctor, bytes32 sigKeyHash, bytes32 kemKeyHash);
    event Granted(address indexed patient, address indexed doctor, bytes32 scopeHash, uint64 epoch, uint64 expiresAt);
    event Revoked(address indexed patient, address indexed doctor, uint64 epoch);
    event EpochChanged(address indexed patient, uint64 epoch);
    event RecordCommitted(address indexed patient, bytes32 root, uint64 version);
    event ConsentRootChanged(address indexed patient, bytes32 root);
    event SearchCommitted(address indexed patient, address indexed doctor, bytes32 commitment, uint256 nonce, uint64 epoch);
    event AuthVerified(address indexed patient, uint256 nullifier);
    event BreakGlass(address indexed patient, address indexed doctor, bytes32 justificationHash);

    constructor(address verifier, bool proofRequired) {
        zkVerifier = ZKVerifier(verifier);
        requireProof = proofRequired;
    }

    function registerDoctor(bytes32 sigKeyHash, bytes32 kemKeyHash) external {
        Doctor storage existing = doctors[msg.sender];
        require(!existing.registered || (existing.sigKeyHash == sigKeyHash && existing.kemKeyHash == kemKeyHash), 'doctor_already_registered');
        doctors[msg.sender] = Doctor(sigKeyHash, kemKeyHash, true);
        emit DoctorRegistered(msg.sender, sigKeyHash, kemKeyHash);
    }
    function grant(address doctor, bytes32 scopeHash, uint64 duration) external {
        require(duration >= 60 && duration <= 31536000, 'expiry_out_of_range');
        _grant(doctor, scopeHash, duration);
    }
    function emergencyGrant(address doctor, bytes32 scopeHash, uint64 duration, bytes32 justification) external {
        require(duration > 0 && duration <= 3600, 'expiry_out_of_range');
        require(justification != bytes32(0), 'missing_justification');
        _grant(doctor, scopeHash, duration);
        emit BreakGlass(msg.sender, doctor, justification);
    }
    function _grant(address doctor, bytes32 scopeHash, uint64 duration) internal {
        require(doctors[doctor].registered, 'unknown_doctor');
        grants[msg.sender][doctor] = Grant(scopeHash, uint64(block.timestamp) + duration, epochs[msg.sender], true);
        emit Granted(msg.sender, doctor, scopeHash, epochs[msg.sender], uint64(block.timestamp) + duration);
    }
    function revoke(address doctor) external {
        require(grants[msg.sender][doctor].active, 'no_active_grant');
        grants[msg.sender][doctor].active = false;
        epochs[msg.sender]++;
        emit Revoked(msg.sender, doctor, epochs[msg.sender]);
        emit EpochChanged(msg.sender, epochs[msg.sender]);
    }
    function reissueGrant(address doctor) external {
        Grant storage g = grants[msg.sender][doctor];
        require(g.active && g.expiresAt >= block.timestamp, 'no_active_grant');
        g.epoch = epochs[msg.sender];
        emit Granted(msg.sender, doctor, g.scopeHash, g.epoch, g.expiresAt);
    }
    function putRecord(bytes32 root, uint64 version) external {
        require(version > recordRoots[msg.sender].version, 'version_not_increasing');
        recordRoots[msg.sender] = RecordRoot(root, version);
        emit RecordCommitted(msg.sender, root, version);
    }
    function setConsentRoot(bytes32 root) external {
        consentRoots[msg.sender] = root;
        emit ConsentRootChanged(msg.sender, root);
    }
    function hasValidGrant(address patient, address doctor, bytes32 scopeHash, uint64 epoch) public view returns (bool) {
        Grant memory g = grants[patient][doctor];
        return g.active && g.expiresAt >= block.timestamp && g.scopeHash == scopeHash && g.epoch == epoch && epochs[patient] == epoch;
    }
    function _checkSearch(address patient, bytes32 scopeHash, uint64 epoch, uint256 nonce) internal view {
        require(hasValidGrant(patient, msg.sender, scopeHash, epoch), 'out_of_scope');
        require(nonce > lastNonces[patient][msg.sender], 'reused_nonce');
    }
    function requestSearch(address patient, bytes32 scopeHash, uint64 epoch, uint256 nonce, bytes32 commitment) external {
        require(!requireProof, 'proof_required');
        _checkSearch(patient, scopeHash, epoch, nonce);
        _commit(patient, epoch, nonce, commitment);
    }
    function _checkProof(address patient, bytes32 scopeHash, uint64 epoch,
        uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c,
        uint256[4] calldata inputs) internal view {
        require(inputs[0] == uint256(consentRoots[patient]), 'old_root');
        require(inputs[2] == uint256(scopeHash) % FIELD && inputs[3] == epoch, 'wrong_statement');
        require(!nullifiers[inputs[1]], 'reused_nullifier');
        require(zkVerifier.verifyProof(a, b, c, inputs), 'bad_proof');
    }
    function verifyAuth(address patient, bytes32 scopeHash, uint64 epoch,
        uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c,
        uint256[4] calldata inputs) external {
        require(hasValidGrant(patient, msg.sender, scopeHash, epoch), 'out_of_scope');
        _checkProof(patient, scopeHash, epoch, a, b, c, inputs);
        nullifiers[inputs[1]] = true;
        emit AuthVerified(patient, inputs[1]);
    }
    function searchWithProof(address patient, bytes32 scopeHash, uint64 epoch, uint256 nonce, bytes32 commitment,
        uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[4] calldata inputs) external {
        _checkSearch(patient, scopeHash, epoch, nonce);
        _checkProof(patient, scopeHash, epoch, a, b, c, inputs);
        nullifiers[inputs[1]] = true;
        emit AuthVerified(patient, inputs[1]);
        _commit(patient, epoch, nonce, commitment);
    }
    function _commit(address patient, uint64 epoch, uint256 nonce, bytes32 commitment) internal {
        lastNonces[patient][msg.sender] = nonce;
        emit SearchCommitted(patient, msg.sender, commitment, nonce, epoch);
    }
}
