"""R5 / Properties 17-19: PIR round trip and server-view regression tests."""
import json

import numpy as np
import pytest
from hypothesis import given, settings, strategies as st

from medvault.config import MedVaultConfig
from medvault.crypto import ed25519_keypair
from medvault.envelope import Scope
from medvault.pir import (PIRParams, PIRServer, PIRError, build_database,
                          pack_slot, unpack_slot, measure_pir)
from medvault.search import IndexEntry, entry_signing_message
from medvault.service import build_world


@settings(max_examples=100, deadline=None, derandomize=True)
@given(payload=st.binary(max_size=32), selected=st.integers(0, 3))
def test_properties_17_18_round_trip_every_slot(payload, selected):
    slots = [pack_slot(bytes([i]) + payload, i + 1, 48) for i in range(4)]
    database = build_database(slots, 48)
    params = PIRParams(4, 48)
    server = PIRServer()
    hint = server.setup(database, params, 42)
    queries = [server.client_query(i, params, hint) for i in range(4)]
    assert {q.size_bytes() for q in queries} == {16}
    for i, query in enumerate(queries):
        answer = server.answer(database, query.query, params)
        assert server.reconstruct(answer, query.state, params, hint) == slots[i]
    assert selected not in server.log[0].values() or selected == 4
    assert not any('index' in entry or 'record_id' in entry for entry in server.log)


def test_property_19_live_retrieve_never_calls_targeted_get(monkeypatch):
    world = build_world(MedVaultConfig(slot_size=128, deterministic=False))
    for i in range(4):
        world.upload_record(f'r{i}', f'body {i}', ['lab'], tag='lab')
    world.grant_scope('doctor_a', Scope.record_tag('lab'))
    monkeypatch.setattr(world.store, 'get', lambda *a, **kw: pytest.fail('targeted get leaked index'))
    for i in range(4):
        result, _ = world.retrieve('doctor_a', f'r{i}')
        assert result['ok'] and result['plaintext'] == f'body {i}'
        assert result['pir']['query_bytes'] == 16
    assert all(row['record_id'] == '*' for row in world.store.access_log)
    assert 'r0' not in json.dumps(world.pir.server.log)


@pytest.mark.parametrize('mode,reason', [('stale', 'stale_version'),
                                       ('modified', 'content_hash_mismatch'),
                                       ('withheld', 'withheld')])
def test_evil_cloud_still_fails_closed_through_pir(mode, reason):
    world = build_world(MedVaultConfig(slot_size=128))
    world.upload_record('r', 'first', ['a'])
    world.upload_record('r', 'second', ['b'])
    world.grant_scope('doctor_a', Scope.record_set(['r']))
    world.set_evil_mode(mode)
    result, _ = world.retrieve('doctor_a', 'r')
    assert not result['ok'] and result['plaintext'] is None and result['reason'] == reason


def test_bounds_and_measurements():
    with pytest.raises(PIRError):
        PIRParams(1025, 32)
    with pytest.raises(PIRError):
        pack_slot(b'oversized', 1, 12)
    with pytest.raises(PIRError):
        unpack_slot(b'bad')
    rows = measure_pir((4, 8), slot_size=32)
    assert [r['query_bytes'] for r in rows] == [16, 32]
    assert all(r['answer_bytes'] == 128 and r['params']['n'] == 1024 for r in rows)


def test_live_keys_cannot_be_reconstructed_from_public_seed():
    config = MedVaultConfig(seed=42, deterministic=False)
    a, b = build_world(config), build_world(config)
    assert a.patient_signing.public_bytes != b.patient_signing.public_bytes
    assert a.doctors['doctor_a'].kem_public != b.doctors['doctor_a'].kem_public
    assert a._index_key('doctor_a', 0) != b._index_key('doctor_a', 0)
    assert a._index_key('doctor_a', 0) == a._index_key('doctor_a', 0)


def test_search_scope_rewrite_and_forged_caller_key():
    world = build_world(MedVaultConfig())
    world.upload_record('lab', 'lab', ['diabetes'], tag='lab')
    world.upload_record('private', 'private', ['secret'], tag='private')
    world.grant_scope('doctor_a', Scope.record_tag('lab'))
    assert world.search('doctor_a', 'secret')[0]['record_ids'] == []
    world.upload_record('lab', 'new', ['newword'], tag='lab')
    assert world.search('doctor_a', 'diabetes')[0]['record_ids'] == []
    intruder = ed25519_keypair()
    token = b'x' * 32
    entry = IndexEntry(token, 'PLANTED', 0, 'doctor_a',
                       intruder.sign(entry_signing_message(token, 'PLANTED', 0, 'doctor_a')))
    assert world.node.add_entry(entry, intruder.public_key(), world.patient_id) == (False, 'bad_entry_signature')
    world.grant_scope('doctor_b', Scope.record_set(['private']))
    assert 'private' not in json.dumps(world.ledger.chain_log())
