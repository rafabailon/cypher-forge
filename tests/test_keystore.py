import json
import os

import pytest

from cipherforge.errors import KeyStoreError
from cipherforge.keystore import KeyStore
from cipherforge.models import LayerName


def test_key_store_round_trips_generated_keys_with_restricted_permissions(tmp_path):
    path = tmp_path / "private" / "keys.json"
    store = KeyStore(path)
    generated = [
        store.create_cipher_key(layer) for layer in LayerName if layer is not LayerName.BASE64
    ]
    integrity = store.get_or_create_integrity_key()

    loaded = KeyStore(path)
    for key in generated:
        assert loaded.get(key.key_id, key.kind) == key.value
    assert loaded.get(integrity.key_id, KeyStore.INTEGRITY_KIND) == integrity.value
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_integrity_key_is_reused(tmp_path):
    store = KeyStore(tmp_path / "keys.json")
    assert store.get_or_create_integrity_key() == store.get_or_create_integrity_key()


def test_missing_key_store_is_created_on_first_key(tmp_path):
    path = tmp_path / "missing" / "keys.json"
    store = KeyStore(path)
    assert not path.exists()
    store.create_cipher_key(LayerName.CAESAR)
    assert path.exists()


def test_existing_key_store_permissions_are_restricted_on_posix(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission bits are not available.")
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"version": KeyStore.VERSION, "keys": {}}))
    path.chmod(0o644)
    KeyStore(path)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "document",
    [
        "{broken",
        json.dumps({"version": 2, "keys": {}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "caesar", "value": "999"}}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "caesar", "value": "many"}}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "vigenere", "value": "abc1"}}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "xor", "value": ""}}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "integrity", "value": "c2hvcnQ="}}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "fernet", "value": "aGVsbG8="}}}),
        json.dumps({"version": 1, "keys": {"key": {"kind": "unknown", "value": "value"}}}),
        json.dumps({"version": 1, "keys": {"": {"kind": "caesar", "value": "3"}}}),
    ],
)
def test_invalid_key_store_fails_explicitly(tmp_path, document):
    path = tmp_path / "keys.json"
    path.write_text(document)
    with pytest.raises(KeyStoreError):
        KeyStore(path)
