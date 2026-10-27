from __future__ import annotations

import base64
import binascii
from abc import ABC, abstractmethod

from cryptography.fernet import Fernet, InvalidToken

from .errors import InvalidBundleError, InvalidKeyError
from .models import LayerName


class CipherLayer(ABC):
    name: LayerName
    requires_key = True

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        raise NotImplementedError

    @staticmethod
    def _key(key: bytes | str | int | None, expected: type) -> bytes | str | int:
        if not isinstance(key, expected):
            raise InvalidKeyError(f"Expected a {expected.__name__} key.")
        return key


class CaesarLayer(CipherLayer):
    name = LayerName.CAESAR

    def encrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        shift = self._shift(key)
        return _shift_ascii_letters(data, shift)

    def decrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        shift = self._shift(key)
        return _shift_ascii_letters(data, -shift)

    @staticmethod
    def _shift(key: bytes | str | int | None) -> int:
        if not isinstance(key, int) or isinstance(key, bool) or not 1 <= key <= 25:
            raise InvalidKeyError("Caesar keys must be integers from 1 to 25.")
        return key


class VigenereLayer(CipherLayer):
    name = LayerName.VIGENERE

    def encrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        return self._transform(data, self._key(key, str), 1)

    def decrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        return self._transform(data, self._key(key, str), -1)

    @staticmethod
    def _transform(data: bytes, key: str, direction: int) -> bytes:
        if not key or not key.isascii() or not key.isalpha():
            raise InvalidKeyError("Vigenere keys must contain ASCII letters only.")
        shifts = [ord(character.lower()) - ord("a") for character in key]
        result = bytearray(data)
        key_index = 0
        for index, value in enumerate(data):
            if 65 <= value <= 90 or 97 <= value <= 122:
                base = 65 if value <= 90 else 97
                shift = direction * shifts[key_index % len(shifts)]
                result[index] = (value - base + shift) % 26 + base
                key_index += 1
        return bytes(result)


class XORLayer(CipherLayer):
    name = LayerName.XOR

    def encrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        return self._transform(data, self._xor_key(key))

    def decrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        return self._transform(data, self._xor_key(key))

    @staticmethod
    def _xor_key(key: bytes | str | int | None) -> bytes:
        if not isinstance(key, bytes) or not key:
            raise InvalidKeyError("XOR keys must be non-empty bytes.")
        return key

    @staticmethod
    def _transform(data: bytes, key: bytes) -> bytes:
        return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


class FernetLayer(CipherLayer):
    name = LayerName.FERNET

    def encrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        return Fernet(self._fernet_key(key)).encrypt(data)

    def decrypt(self, data: bytes, key: bytes | str | int | None) -> bytes:
        try:
            return Fernet(self._fernet_key(key)).decrypt(data)
        except InvalidToken as error:
            raise InvalidBundleError("Fernet authentication failed.") from error

    @staticmethod
    def _fernet_key(key: bytes | str | int | None) -> bytes:
        if isinstance(key, str):
            try:
                key = key.encode("ascii")
            except UnicodeEncodeError as error:
                raise InvalidKeyError("Fernet keys must be ASCII.") from error
        if not isinstance(key, bytes):
            raise InvalidKeyError("Fernet keys must be URL-safe base64 bytes.")
        try:
            Fernet(key)
        except (ValueError, TypeError) as error:
            raise InvalidKeyError("Fernet key is invalid.") from error
        return key


class Base64Layer(CipherLayer):
    name = LayerName.BASE64
    requires_key = False

    def encrypt(self, data: bytes, key: bytes | str | int | None = None) -> bytes:
        self._no_key(key)
        return base64.b64encode(data)

    def decrypt(self, data: bytes, key: bytes | str | int | None = None) -> bytes:
        self._no_key(key)
        try:
            return base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError) as error:
            raise InvalidBundleError("Base64 layer contains invalid data.") from error

    @staticmethod
    def _no_key(key: bytes | str | int | None) -> None:
        if key is not None:
            raise InvalidKeyError("Base64 encoding does not use a key.")


def _shift_ascii_letters(data: bytes, shift: int) -> bytes:
    result = bytearray(data)
    for index, value in enumerate(data):
        if 65 <= value <= 90:
            result[index] = (value - 65 + shift) % 26 + 65
        elif 97 <= value <= 122:
            result[index] = (value - 97 + shift) % 26 + 97
    return bytes(result)


LAYERS: dict[LayerName, CipherLayer] = {
    layer.name: layer
    for layer in (CaesarLayer(), VigenereLayer(), XORLayer(), FernetLayer(), Base64Layer())
}
