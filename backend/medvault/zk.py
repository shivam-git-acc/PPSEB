"""M6: real Circom/snarkjs Groth16 authorization and explicitly labeled fallback.

Groth16/BN254 is classical. Setup is a local, unaudited, single-party dev ceremony.
Patient knows all leaf secrets. Off-chain paths are private; only roots are public.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from .crypto import VerifyKey

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DEPTH = 4
ROUNDS_FULL = 8
# circomlib N_ROUNDS_P, indexed by t - 2: Poseidon(2) has t=3, Poseidon(3) has t=4.
ROUNDS_PARTIAL = {3: 57, 4: 56}
CIRCUITS = Path(__file__).resolve().parents[2] / 'circuits'


class ZKError(ValueError):
    pass


def field_id(value: bytes) -> int:
    return int.from_bytes(value, 'big') % FIELD


@lru_cache(maxsize=2)
def _constants(t: int):
    filename = CIRCUITS / 'build' / f'poseidon_t{t}.json'
    if filename.exists():
        obj = json.loads(filename.read_text())
        return [int(x, 0) for x in obj['C']], [[int(x, 0) for x in r] for r in obj['M']]
    filename = CIRCUITS / 'node_modules/circomlibjs/src/poseidon_constants.json'
    obj = json.loads(filename.read_text())
    return ([int(x, 0) for x in obj['C'][t - 2]],
            [[int(x, 0) for x in r] for r in obj['M'][t - 2]])


def poseidon(*values: int) -> int:
    """circomlib reference Poseidon(2 or 3), not a substitute hash."""
    t = len(values) + 1
    if t not in (3, 4):
        raise ZKError('only Poseidon(2/3) supported')
    constants, matrix = _constants(t)
    partial = ROUNDS_PARTIAL[t]
    half = ROUNDS_FULL // 2
    state = [0] + [int(x) % FIELD for x in values]
    for r in range(ROUNDS_FULL + partial):
        state = [(x + constants[r * t + i]) % FIELD for i, x in enumerate(state)]
        if r < half or r >= half + partial:
            state = [pow(x, 5, FIELD) for x in state]
        else:
            state[0] = pow(state[0], 5, FIELD)
        state = [sum(matrix[i][j] * state[j] for j in range(t)) % FIELD for i in range(t)]
    return state[0]


class ConsentTree:
    """Fixed-depth Poseidon tree; rebuild excludes expired/revoked grants."""
    def __init__(self, grants: list[tuple[str, int, int, int]], depth: int = DEPTH):
        if len(grants) > 2 ** depth:
            raise ZKError('consent tree capacity exceeded')
        self.depth = depth
        self.positions = {doctor: i for i, (doctor, *_rest) in enumerate(grants)}
        leaves = [poseidon(secret, scope, epoch) for _, secret, scope, epoch in grants]
        leaves += [0] * (2 ** depth - len(leaves))
        self.levels = [leaves]
        while len(self.levels[-1]) > 1:
            previous = self.levels[-1]
            self.levels.append([poseidon(previous[i], previous[i + 1])
                                for i in range(0, len(previous), 2)])
        self.root = self.levels[-1][0]

    def path(self, doctor: str) -> tuple[list[int], list[int]]:
        index = self.positions[doctor]
        elements, bits = [], []
        for level in self.levels[:-1]:
            elements.append(level[index ^ 1])
            bits.append(index & 1)
            index //= 2
        return elements, bits


def signed_statement(doctor_id: str, scope_hash: bytes, epoch: int) -> bytes:
    return b'medvault-signed-consent-v1:' + json.dumps(
        [doctor_id, scope_hash.hex(), epoch], separators=(',', ':')).encode()


class ZKAuthorisation:
    def __init__(self, mode: str = 'auto'):
        if mode not in ('auto', 'groth16', 'signed'):
            raise ZKError('unknown proof mode')
        self.mode = ('groth16' if self.available() else 'signed') if mode == 'auto' else mode
        if self.mode == 'groth16' and not self.available():
            raise ZKError('build circuits first: npm --prefix circuits run build')
        self.last_verification_ms = 0.0

    @staticmethod
    def available() -> bool:
        # runner.js imports snarkjs, so the prover needs the installed package as
        # well as the (committed) build. Without it a fresh clone used to pick
        # Groth16 in auto mode and fail at the first proof; now auto falls back
        # to the labelled signed mode until `npm --prefix circuits ci` is run.
        return shutil.which('node') is not None and all((CIRCUITS / p).exists() for p in (
            'build/auth_js/auth.wasm', 'build/auth_final.zkey',
            'build/verification_key.json', 'build/setup_meta.json',
            'node_modules/snarkjs/package.json'))

    @property
    def label(self) -> str:
        return ('Groth16 BN254 — classical, single-party DEV setup' if self.mode == 'groth16'
                else 'SIGNED CONSENT FALLBACK — not zero knowledge')

    def run(self, data: dict) -> dict:
        try:
            completed = subprocess.run([shutil.which('node'), str(CIRCUITS / 'runner.js')],
                input=json.dumps(data), capture_output=True, text=True, timeout=120)
            if completed.returncode:
                raise ZKError('proof operation failed; no witness disclosed')
            return json.loads(completed.stdout)
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            raise ZKError('ZK toolchain operation failed') from exc

    def generate_proof(self, secret_s: int, scope_id: int, nonce: int,
                       path_elements: list[int], path_indices: list[int],
                       root: int, epoch_tag: int) -> dict:
        if self.mode != 'groth16':
            raise ZKError('Groth16 unavailable in signed fallback mode')
        witness = dict(secret_s=str(secret_s), scope_id=str(scope_id), nonce=str(nonce),
                       pathElements=list(map(str, path_elements)), pathIndices=path_indices,
                       root=str(root), epoch_tag=str(epoch_tag),
                       nullifier=str(poseidon(secret_s, nonce)))
        result = self.run({'op': 'prove', 'witness': witness})
        return {'kind': 'groth16', 'proof': result['proof'],
                'public_inputs': result['publicSignals'],
                'proving_ms': round(result['elapsed_ms'], 3)}

    def verify_proof(self, proof: dict, public_inputs: list[int | str]) -> bool:
        try:
            if len(public_inputs) != 4 or any(not 0 <= int(x) < FIELD for x in public_inputs):
                return False
            result = self.run({'op': 'verify', 'proof': proof,
                               'publicSignals': list(map(str, public_inputs))})
            self.last_verification_ms = result['elapsed_ms']
            return bool(result['valid'])
        except (ZKError, TypeError, ValueError, KeyError):
            return False

    def check_request(self, req, ledger, patient_id: str, patient_key: VerifyKey) -> tuple[bool, bytes | None]:
        """Check without consuming state. All gates commit together in Gateway."""
        data = req.zk_proof
        if not isinstance(data, dict):
            return False, None
        if self.mode == 'signed':
            try:
                ok = data.get('kind') == 'signed' and patient_key.verify(
                    bytes.fromhex(data['signature']),
                    signed_statement(req.doctor_id, req.scope_hash, req.epoch))
                return ok, None
            except (KeyError, TypeError, ValueError):
                return False, None
        try:
            root, nullifier, scope, epoch = map(int, data['public_inputs'])
            nbytes = nullifier.to_bytes(32, 'big')
            if (data.get('kind') != 'groth16' or root != field_id(ledger.consent_root(patient_id))
                    or scope != field_id(req.scope_hash) or epoch != req.epoch
                    or ledger.is_nullifier_used(nbytes)):
                return False, None
            return self.verify_proof(data['proof'], data['public_inputs']), nbytes
        except (ValueError, TypeError, KeyError, OverflowError):
            return False, None
