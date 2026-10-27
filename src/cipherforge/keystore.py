from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet

from .errors import InvalidKeyError, KeyStoreError
from .models import LayerName

KeyMaterial = bytes | str | int


@dataclass(frozen=True)
class StoredKey:
    key_id: str
    kind: str
    value: KeyMaterial


class KeyStore:
    VERSION = 1
    INTEGRITY_KIND = "integrity"

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()
        self._keys: dict[str, StoredKey] = {}
        self._load()

    def create_cipher_key(self, layer: LayerName) -> StoredKey:
        if layer is LayerName.CAESAR:
            kind, value = layer.value, secrets.randbelow(25) + 1
        elif layer is LayerName.VIGENERE:
            kind, value = (
                layer.value,
                "".join(chr(secrets.randbelow(26) + ord("a")) for _ in range(24)),
            )
        elif layer is LayerName.XOR:
            kind, value = layer.value, secrets.token_bytes(32)
        elif layer is LayerName.FERNET:
            kind, value = layer.value, Fernet.generate_key()
        else:
            raise InvalidKeyError(f"{layer.value} does not require a key.")
        stored = StoredKey(self._new_id(), kind, value)
        self._keys[stored.key_id] = stored
        self._save()
        return stored

    def get(self, key_id: str, expected_kind: str) -> KeyMaterial:
        stored = self._keys.get(key_id)
        if stored is None or stored.kind != expected_kind:
            raise InvalidKeyError(f"Missing or incompatible key: {key_id}.")
        return stored.value

    def get_or_create_integrity_key(self) -> StoredKey:
        for key in self._keys.values():
            if key.kind == self.INTEGRITY_KIND:
                return key
        stored = StoredKey(self._new_id(), self.INTEGRITY_KIND, secrets.token_bytes(32))
        self._keys[stored.key_id] = stored
        self._save()
        return stored

    @staticmethod
    def _new_id() -> str:
        return f"key_{uuid.uuid4().hex}"

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            if self.path.is_symlink():
                raise KeyStoreError("Refusing to load a key store through a symbolic link.")
            if os.name == "posix":
                os.chmod(self.path, 0o600)
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if (
                not isinstance(document, dict)
                or document.get("version") != self.VERSION
                or not isinstance(document.get("keys"), dict)
            ):
                raise KeyStoreError("Key store format is unsupported or malformed.")
            for key_id, raw in document["keys"].items():
                if (
                    not isinstance(key_id, str)
                    or not key_id
                    or not isinstance(raw, dict)
                    or not isinstance(raw.get("kind"), str)
                    or not isinstance(raw.get("value"), str)
                ):
                    raise KeyStoreError("Key store contains a malformed key entry.")
                self._keys[key_id] = StoredKey(
                    key_id, raw["kind"], _decode_key(raw["kind"], raw["value"])
                )
        except (OSError, json.JSONDecodeError, AttributeError) as error:
            raise KeyStoreError(f"Cannot read key store at {self.path}.") from error

    def _save(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        document = {
            "version": self.VERSION,
            "keys": {
                key_id: {"kind": key.kind, "value": _encode_key(key.value)}
                for key_id, key in sorted(self._keys.items())
            },
        }
        temporary_path: Path | None = None
        try:
            descriptor, filename = tempfile.mkstemp(
                prefix=f".{self.path.name}.", dir=self.path.parent
            )
            temporary_path = Path(filename)
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.is_symlink():
                raise KeyStoreError("Refusing to replace a key store through a symbolic link.")
            os.replace(temporary_path, self.path)
            temporary_path = None
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        except OSError as error:
            raise KeyStoreError(f"Cannot securely write key store at {self.path}.") from error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def _encode_key(value: KeyMaterial) -> str:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return str(value)


def _decode_key(kind: str, value: str) -> KeyMaterial:
    if kind == LayerName.CAESAR.value:
        try:
            result = int(value)
        except ValueError as error:
            raise KeyStoreError("Key store contains an invalid Caesar key.") from error
        if not 1 <= result <= 25:
            raise KeyStoreError("Key store contains an out-of-range Caesar key.")
        return result
    if kind == LayerName.VIGENERE.value:
        if not value or not value.isascii() or not value.isalpha():
            raise KeyStoreError("Key store contains an invalid Vigenere key.")
        return value
    if kind in (LayerName.XOR.value, LayerName.FERNET.value, KeyStore.INTEGRITY_KIND):
        try:
            result_bytes = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as error:
            raise KeyStoreError(f"Key store contains invalid {kind} key data.") from error
        if not result_bytes:
            raise KeyStoreError(f"Key store contains an empty {kind} key.")
        if kind == KeyStore.INTEGRITY_KIND and len(result_bytes) != 32:
            raise KeyStoreError("Key store contains an invalid integrity key.")
        if kind == LayerName.FERNET.value:
            try:
                Fernet(result_bytes)
            except (ValueError, TypeError) as error:
                raise KeyStoreError("Key store contains an invalid Fernet key.") from error
        return result_bytes
    raise KeyStoreError(f"Key store contains an unsupported key type: {kind}.")
