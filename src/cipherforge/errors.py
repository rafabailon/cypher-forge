class CipherForgeError(Exception):
    """Base class for expected application errors."""


class InvalidKeyError(CipherForgeError):
    """Raised when a key is missing or incompatible with a cipher layer."""


class InvalidBundleError(CipherForgeError):
    """Raised when an encrypted bundle is malformed or has been modified."""


class IntegrityError(InvalidBundleError):
    """Raised when bundle authentication fails."""


class KeyStoreError(CipherForgeError):
    """Raised when a local key store cannot be read or safely written."""


class FileAccessError(CipherForgeError):
    """Raised when a message or bundle file cannot be read or written."""
