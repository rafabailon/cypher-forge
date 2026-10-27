import pytest
from cryptography.fernet import Fernet

from cipherforge.errors import InvalidBundleError, InvalidKeyError
from cipherforge.layers import (
    Base64Layer,
    CaesarLayer,
    FernetLayer,
    VigenereLayer,
    XORLayer,
)

PLAINTEXT = "Meet at 09:30, café! 🌒".encode()


@pytest.mark.parametrize(
    ("layer", "key"),
    [
        (CaesarLayer(), 11),
        (VigenereLayer(), "SilverMoon"),
        (XORLayer(), b"\x00\x03\x10binary-key"),
        (FernetLayer(), Fernet.generate_key()),
        (Base64Layer(), None),
    ],
)
def test_cipher_layers_round_trip_bytes(layer, key):
    encrypted = layer.encrypt(PLAINTEXT, key)
    assert encrypted != PLAINTEXT
    assert layer.decrypt(encrypted, key) == PLAINTEXT


def test_caesar_preserves_case_punctuation_and_non_ascii():
    layer = CaesarLayer()
    assert layer.encrypt("Abc XYZ! café".encode(), 3) == b"Def ABC! fdi\xc3\xa9"


@pytest.mark.parametrize("key", [0, 26, -1, True, "3"])
def test_caesar_rejects_invalid_keys(key):
    with pytest.raises(InvalidKeyError):
        CaesarLayer().encrypt(b"text", key)


@pytest.mark.parametrize("key", ["", "clé", "abc123", 12, b"letters"])
def test_vigenere_rejects_invalid_keys(key):
    with pytest.raises(InvalidKeyError):
        VigenereLayer().encrypt(b"text", key)


@pytest.mark.parametrize("key", [b"", "text", 4, None])
def test_xor_rejects_invalid_keys(key):
    with pytest.raises(InvalidKeyError):
        XORLayer().encrypt(b"text", key)


def test_fernet_rejects_invalid_key_and_modified_token():
    layer = FernetLayer()
    with pytest.raises(InvalidKeyError):
        layer.encrypt(b"text", b"not-a-fernet-key")
    token = layer.encrypt(b"text", Fernet.generate_key())
    damaged = token[:-1] + (b"A" if token[-1:] != b"A" else b"B")
    with pytest.raises(InvalidBundleError, match="authentication failed"):
        layer.decrypt(damaged, Fernet.generate_key())


def test_base64_rejects_key_and_invalid_encoded_payload():
    layer = Base64Layer()
    with pytest.raises(InvalidKeyError):
        layer.encrypt(b"text", b"unused")
    with pytest.raises(InvalidBundleError, match="Base64"):
        layer.decrypt(b"not base64!", None)
