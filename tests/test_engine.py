import json

import pytest

from cipherforge.engine import CipherEngine
from cipherforge.errors import InvalidBundleError, InvalidKeyError
from cipherforge.keystore import KeyStore
from cipherforge.models import CipherBundle, LayerName

ALL_LAYERS = tuple(LayerName)


@pytest.fixture
def engine(tmp_path):
    return CipherEngine(KeyStore(tmp_path / "config" / "keys.json"))


@pytest.mark.parametrize(
    "layers",
    [
        (LayerName.CAESAR,),
        (LayerName.VIGENERE, LayerName.BASE64),
        (LayerName.XOR, LayerName.CAESAR, LayerName.BASE64),
        (LayerName.CAESAR, LayerName.XOR, LayerName.FERNET, LayerName.BASE64),
        ALL_LAYERS,
        (LayerName.FERNET, LayerName.FERNET),
    ],
)
def test_pipeline_round_trips_unicode_and_empty_messages(engine, layers):
    for message in ("Cipher Forge — café 🌒", ""):
        bundle = engine.encrypt(message, layers)
        assert engine.decrypt(bundle) == message
        assert engine.verify(bundle)


def test_json_bundle_round_trip(engine):
    serialized = engine.encrypt_to_json("secure-ish demo", ALL_LAYERS)
    assert engine.decrypt_from_json(serialized) == "secure-ish demo"
    assert engine.verify_json(serialized)


def test_empty_pipeline_is_rejected(engine):
    with pytest.raises(InvalidBundleError, match="at least one"):
        engine.encrypt("message", ())


def test_invalid_layers_are_rejected_before_keys_are_created(engine):
    with pytest.raises(InvalidBundleError, match="Unknown cipher layer"):
        engine.encrypt("message", (LayerName.CAESAR, "rot13"))  # type: ignore[arg-type]
    assert not engine.key_store.path.exists()


def test_modified_payload_and_layer_metadata_fail_integrity(engine):
    bundle = engine.encrypt("tamper check", (LayerName.CAESAR, LayerName.FERNET))
    altered_payload = bundle.payload[:-1] + bytes([bundle.payload[-1] ^ 1])
    with pytest.raises(InvalidBundleError, match="integrity"):
        engine.verify(
            CipherBundle(
                bundle.layers,
                altered_payload,
                bundle.integrity_key_id,
                bundle.integrity_tag,
            )
        )

    altered_layers = (LayerName.BASE64,)
    modified_metadata = (bundle.layers[0].__class__(altered_layers[0]),)
    with pytest.raises(InvalidBundleError, match="integrity"):
        engine.verify(
            CipherBundle(
                modified_metadata,
                bundle.payload,
                bundle.integrity_key_id,
                bundle.integrity_tag,
            )
        )


@pytest.mark.parametrize(
    "serialized",
    [
        "not-json",
        "{}",
        json.dumps({"version": 999, "layers": [], "payload": "", "integrity": {}}),
        json.dumps({"version": True, "layers": [], "payload": "", "integrity": {}}),
        json.dumps({"version": 1, "layers": [], "payload": "", "integrity": {}}),
        json.dumps(
            {
                "version": 1,
                "layers": [{"name": "not-a-cipher"}],
                "payload": "",
                "integrity": {
                    "key_id": "id",
                    "tag": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                },
            }
        ),
        json.dumps(
            {
                "version": 1,
                "layers": [{"name": "caesar", "key_id": ""}],
                "payload": "",
                "integrity": {
                    "key_id": "id",
                    "tag": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                },
            }
        ),
        json.dumps(
            {
                "version": 1,
                "layers": [{"name": "base64", "key_id": "unexpected"}],
                "payload": "",
                "integrity": {
                    "key_id": "id",
                    "tag": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                },
            }
        ),
    ],
)
def test_rejects_malformed_bundles(engine, serialized):
    with pytest.raises(InvalidBundleError):
        engine.decrypt_from_json(serialized)


def test_missing_key_is_reported_after_valid_bundle_authentication(engine, tmp_path):
    bundle = engine.encrypt("key test", (LayerName.CAESAR,))
    original_keys = json.loads(engine.key_store.path.read_text())
    integrity_entries = {
        key_id: entry
        for key_id, entry in original_keys["keys"].items()
        if entry["kind"] == KeyStore.INTEGRITY_KIND
    }
    other_path = tmp_path / "other-keys.json"
    other_path.write_text(json.dumps({"version": KeyStore.VERSION, "keys": integrity_entries}))
    other_engine = CipherEngine(KeyStore(other_path))
    with pytest.raises(InvalidKeyError, match="Missing or incompatible"):
        other_engine.decrypt(bundle)
