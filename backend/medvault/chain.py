"""M4/M6 local Hardhat ledger. Contract state is authoritative for authorization.

Off-chain cache contains scope definitions/tags only; chain stores hashes. Uses
unlocked local DEV accounts, never production credentials or external RPCs.
"""
from __future__ import annotations

import json
from pathlib import Path

from .consent import MemoryConsentLedger, ConsentError

CONTRACTS = Path(__file__).resolve().parents[2] / 'contracts'


def proof_calldata(bundle: dict):
    if not bundle or not bundle.get("proof"):
        # The gateway only reaches this point with a verified proof, so a request
        # without one is a bug on our side; refuse rather than raise a TypeError.
        raise ConsentError("missing_proof", "the contract requires a Groth16 proof")
    p = bundle['proof']
    return (list(map(int, p['pi_a'][:2])),
            [[int(p['pi_b'][0][1]), int(p['pi_b'][0][0])],
             [int(p['pi_b'][1][1]), int(p['pi_b'][1][0])]],
            list(map(int, p['pi_c'][:2])), list(map(int, bundle['public_inputs'])))


class HardhatConsentLedger(MemoryConsentLedger):
    def __init__(self, *, require_proof=True, rpc='http://127.0.0.1:8545'):
        from web3 import Web3
        if rpc != 'http://127.0.0.1:8545':
            raise ConsentError('local_rpc_only')
        self.web3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 15}))
        if not self.web3.is_connected():
            raise ConsentError('chain_unavailable', 'Start the local Hardhat network first')
        if self.web3.eth.chain_id != 31337:
            raise ConsentError('wrong_chain', 'Only local Hardhat DEV chain 31337 allowed')
        self.accounts = self.web3.eth.accounts
        self.patient_account = self.accounts[0]
        self._addresses = {}
        self.gas_receipts = []
        generated = self._deploy('Groth16Verifier', []) if require_proof else None
        wrapper = self._deploy('ZKVerifier', [generated.address]) if require_proof else None
        self.contract = self._deploy('ConsentRegistry', [wrapper.address if wrapper else
                                       '0x0000000000000000000000000000000000000000', require_proof])
        self.require_proof = require_proof
        self.start_block = self.web3.eth.block_number
        super().__init__(clock=lambda: self.web3.eth.get_block('latest')['timestamp'])

    @property
    def backend_label(self):
        return 'hardhat-local-chain'

    def _artifact(self, name):
        filename = CONTRACTS / f'artifacts/src/{name}.sol/{name}.json'
        if not filename.exists():
            raise ConsentError('contracts_not_compiled', 'npm --prefix contracts run compile')
        return json.loads(filename.read_text())

    def _deploy(self, name, args):
        obj = self._artifact(name)
        contract = self.web3.eth.contract(abi=obj['abi'], bytecode=obj['bytecode'])
        receipt = self._tx(contract.constructor(*args), self.patient_account, 'deploy_' + name)
        return self.web3.eth.contract(address=receipt['contractAddress'], abi=obj['abi'])

    def _tx(self, fn, sender, operation):
        try:
            receipt = self.web3.eth.wait_for_transaction_receipt(fn.transact({'from': sender}), timeout=30)
            if receipt['status'] != 1:
                raise ConsentError('chain_rejected')
            self.gas_receipts.append({'operation': operation, 'gas': receipt['gasUsed'],
                                      'transaction_hash': receipt['transactionHash'].hex()})
            return receipt
        except ConsentError:
            raise
        except Exception as exc:
            raise ConsentError('chain_rejected', 'Contract rejected the transaction') from exc

    def _address(self, doctor):
        if doctor not in self._addresses:
            index = len(self._addresses) + 1
            if index >= len(self.accounts):
                raise ConsentError('doctor_capacity')
            self._addresses[doctor] = self.accounts[index]
        return self._addresses[doctor]

    def register_doctor(self, doctor_id, sig_key_hash, kem_key_hash):
        self._tx(self.contract.functions.registerDoctor(sig_key_hash, kem_key_hash),
                 self._address(doctor_id), 'register_doctor')
        return super().register_doctor(doctor_id, sig_key_hash, kem_key_hash)

    def grant(self, patient_id, doctor_id, scope, expiry_seconds):
        self._validate_grant_inputs(patient_id, doctor_id, expiry_seconds)
        self._tx(self.contract.functions.grant(self._address(doctor_id), scope.scope_hash(), expiry_seconds),
                 self.patient_account, 'grant')
        return super().grant(patient_id, doctor_id, scope, expiry_seconds)

    def emergency_grant(self, patient_id, doctor_id, scope, justification_hash, expiry_seconds):
        self._tx(self.contract.functions.emergencyGrant(self._address(doctor_id), scope.scope_hash(),
                 expiry_seconds, justification_hash), self.patient_account, 'emergency_grant')
        return super().emergency_grant(patient_id, doctor_id, scope, justification_hash, expiry_seconds)

    def revoke(self, patient_id, doctor_id):
        self._tx(self.contract.functions.revoke(self._address(doctor_id)), self.patient_account, 'revoke')
        grant = self._grants[(patient_id, doctor_id)]
        grant.active = False
        grant.revoked = True
        epoch = self.current_epoch(patient_id)
        self._epochs[patient_id] = epoch
        self._log('revoke', patient_id, doctor_id, epoch - 1)
        self._log('epoch_change', patient_id, doctor_id, epoch)
        return epoch, self.now()

    def reissue_grant(self, patient_id, doctor_id, epoch):
        self._tx(self.contract.functions.reissueGrant(self._address(doctor_id)), self.patient_account, 'reissue_grant')
        return super().reissue_grant(patient_id, doctor_id, epoch)

    def current_epoch(self, patient_id):
        return self.contract.functions.epochs(self.patient_account).call()

    def has_valid_grant(self, doctor_id, scope_hash, epoch):
        return self.contract.functions.hasValidGrant(self.patient_account, self._address(doctor_id), scope_hash, epoch).call()

    def is_authorized(self, doctor_id, record_id):
        for (patient, doctor), grant in self._grants.items():
            if doctor == doctor_id and grant.scope.contains(record_id, self._notes):
                return self.has_valid_grant(doctor, grant.scope_hash, self.current_epoch(patient))
        return False

    def put_record(self, patient_id, root, version):
        self._tx(self.contract.functions.putRecord(root, version), self.patient_account, 'put_record')
        return super().put_record(patient_id, root, version)

    def record_root(self, patient_id):
        root, version = self.contract.functions.recordRoots(self.patient_account).call()
        return bytes(root), version

    def set_consent_root(self, patient_id, root):
        self._tx(self.contract.functions.setConsentRoot(root), self.patient_account, 'consent_root')
        return super().set_consent_root(patient_id, root)

    def consent_root(self, patient_id):
        return bytes(self.contract.functions.consentRoots(self.patient_account).call())

    def is_nullifier_used(self, nullifier):
        return self.contract.functions.nullifiers(int.from_bytes(nullifier, 'big')).call()

    def commit_search(self, patient_id, req, commitment, nullifier):
        args = [self.patient_account, req.scope_hash, req.epoch, req.nonce, commitment]
        fn = (self.contract.functions.searchWithProof(*args, *proof_calldata(req.zk_proof))
              if self.require_proof else self.contract.functions.requestSearch(*args))
        self._tx(fn, self._address(req.doctor_id), 'search_with_proof' if self.require_proof else 'search')
        super().request_search(patient_id, req.doctor_id, commitment, req.nonce)
        if nullifier is not None:
            super().add_nullifier(nullifier)

    def advance_clock(self, seconds):
        self.web3.provider.make_request('evm_increaseTime', [seconds])
        self.web3.provider.make_request('evm_mine', [])
        return self.now()

    def chain_log(self):
        events = []
        abi_events = [obj['name'] for obj in self.contract.abi if obj['type'] == 'event']
        logs = self.web3.eth.get_logs({'address': self.contract.address,
                                      'fromBlock': self.start_block, 'toBlock': 'latest'})
        for log in logs:
            for name in abi_events:
                try:
                    decoded = getattr(self.contract.events, name)().process_log(log)
                    args = {k: v.hex() if isinstance(v, bytes) else v for k, v in decoded['args'].items()}
                    events.append({'type': name, 'block': log['blockNumber'],
                                   'log_index': log['logIndex'], **args})
                    break
                except Exception:
                    continue
        return events

    def audit_view(self):
        return self.chain_log()
