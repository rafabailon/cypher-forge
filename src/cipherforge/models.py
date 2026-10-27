from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .errors import InvalidBundleError


class LayerName(str, Enum):
    CAESAR = "caesar"
    VIGENERE = "vigenere"
    XOR = "xor"
    FERNET = "fernet"
    BASE64 = "base64"


@dataclass(frozen=True)
class LayerReference:
    name: LayerName
    key_id: str | None = None

    def to_dict(self) -> dict[str, str]:
        result = {"name": self.name.value}
        if self.key_id is not None:
            result["key_id"] = self.key_id
        return result

    @classmethod
    def from_dict(cls, value: Any) -> LayerReference:
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            raise InvalidBundleError("Each layer must have a valid name.")
        try:
            name = LayerName(value["name"])
        except ValueError as error:
            raise InvalidBundleError(f"Unsupported cipher layer: {value['name']!r}.") from error
        key_id = value.get("key_id")
        if key_id is not None and (not isinstance(key_id, str) or not key_id):
            raise InvalidBundleError("Layer key identifiers must be non-empty strings.")
        if (name is LayerName.BASE64) == (key_id is not None):
            raise InvalidBundleError("Only keyed layers must include a key identifier.")
        return cls(name=name, key_id=key_id)


@dataclass(frozen=True)
class CipherBundle:
    layers: tuple[LayerReference, ...]
    payload: bytes
    integrity_key_id: str
    integrity_tag: bytes

    VERSION = 1

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.VERSION,
            "layers": [layer.to_dict() for layer in self.layers],
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "integrity": {"key_id": self.integrity_key_id},
        }

    def authenticated_bytes(self) -> bytes:
        return json.dumps(
            self._unsigned_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    def to_json(self) -> str:
        document = self._unsigned_dict()
        document["integrity"]["tag"] = base64.b64encode(self.integrity_tag).decode("ascii")
        return json.dumps(document, indent=2, ensure_ascii=True)

    @classmethod
    def from_json(cls, serialized: str) -> CipherBundle:
        try:
            value = json.loads(serialized)
        except (json.JSONDecodeError, TypeError) as error:
            raise InvalidBundleError("Bundle must be valid JSON.") from error
        if (
            not isinstance(value, dict)
            or type(value.get("version")) is not int
            or value["version"] != cls.VERSION
        ):
            raise InvalidBundleError("Unsupported or missing bundle version.")
        raw_layers = value.get("layers")
        if not isinstance(raw_layers, list) or not raw_layers:
            raise InvalidBundleError("Bundle must contain at least one cipher layer.")
        layers = tuple(LayerReference.from_dict(layer) for layer in raw_layers)
        payload = _decode_base64(value.get("payload"), "payload")
        integrity = value.get("integrity")
        if not isinstance(integrity, dict):
            raise InvalidBundleError("Bundle integrity metadata is missing.")
        key_id = integrity.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise InvalidBundleError("Bundle integrity key identifier is invalid.")
        tag = _decode_base64(integrity.get("tag"), "integrity tag")
        if len(tag) != 32:
            raise InvalidBundleError("Bundle integrity tag has an invalid length.")
        return cls(layers, payload, key_id, tag)


def _decode_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidBundleError(f"Bundle {label} must be base64 text.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidBundleError(f"Bundle {label} is not valid base64.") from error
