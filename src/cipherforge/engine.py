from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

from .errors import IntegrityError, InvalidBundleError
from .keystore import KeyStore
from .layers import LAYERS
from .models import CipherBundle, LayerName, LayerReference


class CipherEngine:
    def __init__(self, key_store: KeyStore) -> None:
        self.key_store = key_store

    def encrypt(self, message: str, layers: Iterable[LayerName]) -> CipherBundle:
        selected_layers = tuple(layers)
        if not selected_layers:
            raise InvalidBundleError("Choose at least one cipher layer.")
        if not isinstance(message, str):
            raise TypeError("Message must be text.")
        # Validate every layer before creating keys so invalid input cannot
        # leave orphaned entries in the key store.
        for name in selected_layers:
            if not isinstance(name, LayerName):
                raise InvalidBundleError(f"Unknown cipher layer: {name!r}.")
        try:
            payload = message.encode("utf-8")
        except UnicodeEncodeError as error:
            raise InvalidBundleError("Message cannot be encoded as UTF-8.") from error

        references: list[LayerReference] = []
        for name in selected_layers:
            layer = LAYERS[name]
            if layer.requires_key:
                stored_key = self.key_store.create_cipher_key(name)
                payload = layer.encrypt(payload, stored_key.value)
                references.append(LayerReference(name, stored_key.key_id))
            else:
                payload = layer.encrypt(payload, None)
                references.append(LayerReference(name))

        integrity_key = self.key_store.get_or_create_integrity_key()
        unsigned = CipherBundle(tuple(references), payload, integrity_key.key_id, b"")
        tag = hmac.new(integrity_key.value, unsigned.authenticated_bytes(), hashlib.sha256).digest()
        return CipherBundle(tuple(references), payload, integrity_key.key_id, tag)

    def decrypt(self, bundle: CipherBundle) -> str:
        self.verify(bundle)
        payload = bundle.payload
        for reference in reversed(bundle.layers):
            layer = LAYERS[reference.name]
            key = (
                self.key_store.get(reference.key_id, reference.name.value)
                if reference.key_id is not None
                else None
            )
            payload = layer.decrypt(payload, key)
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InvalidBundleError("Decrypted data is not valid UTF-8 text.") from error

    def verify(self, bundle: CipherBundle) -> bool:
        key = self.key_store.get(bundle.integrity_key_id, KeyStore.INTEGRITY_KIND)
        expected_tag = hmac.new(key, bundle.authenticated_bytes(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, bundle.integrity_tag):
            raise IntegrityError("Bundle integrity verification failed.")
        return True

    def encrypt_to_json(self, message: str, layers: Iterable[LayerName]) -> str:
        return self.encrypt(message, layers).to_json()

    def decrypt_from_json(self, serialized: str) -> str:
        return self.decrypt(CipherBundle.from_json(serialized))

    def verify_json(self, serialized: str) -> bool:
        return self.verify(CipherBundle.from_json(serialized))
