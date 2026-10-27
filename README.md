# Cipher Forge: Multi-Layer Cipher Engine

Cipher Forge is an educational Python application for composing reversible message transformations. It includes classic classroom ciphers, XOR, Base64 encoding, authenticated Fernet encryption, a local key store, an interactive terminal menu, scriptable CLI commands, and an automated pytest suite.

> **Security note:** Caesar, Vigenere, and repeating-key XOR are educational examples, not secure encryption. Base64 is encoding, not encryption. For confidentiality and authenticity, use Fernet on its own or as the final encryption layer in a chain. Protect the local key store and keep a backup: losing it makes bundles undecryptable.

## Requirements

- Python 3.10 or newer
- pip

## Install and run

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
cipherforge
```

The same menu can be launched with `python -m cipherforge`.

## Usage

### Interactive menu

Run `cipherforge` without arguments to encrypt a message, decrypt a saved bundle, verify a bundle's integrity, or exit. During encryption, enter a comma-separated layer sequence, for example:

```text
caesar,vigenere,xor,fernet,base64
```

Layers are applied from left to right and reversed automatically during decryption, so the last layer is the outermost transformation. A JSON bundle contains the layer sequence, key identifiers, encrypted payload, and an HMAC-SHA-256 integrity tag.

### Scriptable commands

Cipher Forge also exposes non-interactive commands for scripts and pipelines:

```bash
# Encrypt a file and write the bundle to another file.
cipherforge encrypt --layers caesar,vigenere,xor,fernet,base64 \
  --input message.txt --output bundle.json

# Verify and decrypt a bundle file.
cipherforge verify bundle.json
cipherforge decrypt bundle.json

# Read the message from stdin and write the bundle to stdout.
printf 'meet me at dawn' | cipherforge encrypt --layers caesar,base64 > bundle.json
cipherforge decrypt bundle.json
```

Use `-` explicitly to read a message or bundle from stdin, and `--output -` to force bundle output to stdout. The key-store location is reported on stderr so stdout remains clean when it carries a bundle or decrypted message.

`cipherforge --help` lists all options. Exit codes are `0` for success, `1` for an expected application error, `2` for invalid command-line usage, and `130` when an interactive session is cancelled.

> Prefer `--input` or stdin over `--message`: command-line arguments can remain in shell history and process listings. For messages containing trailing newlines, use `--input` or stdin with the exact bytes you want to encrypt.

### Key store

Secret key material is kept separately from bundles in a local key store. The default path is `~/.config/cipherforge/keys.json`; set `CIPHERFORGE_KEY_STORE` to use another path. `XDG_CONFIG_HOME` is respected when it is set.

Each encryption generates fresh keys for keyed layers, and the key store grows as a result. Keep the store safe and backed up: it is required to decrypt every bundle it created.

On POSIX systems, Cipher Forge creates the key store with owner-only permissions and replaces it atomically. Permission changes are skipped on platforms that do not expose POSIX mode bits. The key store is intentionally not encrypted at rest: restrict access to your account and do not share it. The HMAC verifies bundle integrity but does not provide identity or non-repudiation because the shared local key can generate valid tags.

## Cipher layers

| Layer | Key | Behavior |
|---|---|---|
| `caesar` | Random shift from 1 to 25 | Shifts ASCII letters; preserves case and leaves other bytes unchanged. |
| `vigenere` | Random ASCII-letter key | Repeating-key shifts on ASCII letters; leaves other bytes unchanged. |
| `xor` | Random 32-byte key | Repeating-key XOR; reversible but cryptographically weak. |
| `fernet` | Random Fernet key | Authenticated symmetric encryption using the `cryptography` Fernet implementation. |
| `base64` | None | Reversible text encoding for displaying arbitrary bytes. |

Run `cipherforge layers` to list available layers from the CLI.

Fernet bundles are time-stamped and authenticated. A malformed, modified, or incorrectly keyed Fernet token fails closed with an error.

## Tests and quality checks

```bash
python -m pytest
ruff check src tests
ruff format --check src tests
```

Tests cover individual layer reversibility, key validation, complete mixed-layer pipelines, Unicode and empty messages, malformed and tampered bundles, strict bundle metadata, key-store permissions and validation, orphan-key prevention, and both interactive and scriptable CLI flows.

## Project structure

```text
src/cipherforge/   Application, cipher layers, key store, bundle format, and CLI
tests/             pytest unit and integration coverage
```

## Scope

Cipher Forge processes user-provided local text and does not make network requests. It is intended for learning and local experimentation, not for protecting real-world sensitive data. For production applications, use a vetted cryptographic design and established key-management infrastructure rather than composing classical ciphers.

## Changelog

### 1.1.0

- Renamed the project, Python package, CLI command, environment variable, and documentation from CrypticWeave to **Cipher Forge** (`cipherforge`, `CIPHERFORGE_KEY_STORE`).
- Added non-interactive `encrypt`, `decrypt`, and `verify` commands while keeping the interactive menu.
- Added file and stdin input/output support, plus `--version` and consistent exit codes.
- Validated all requested layers before creating keys, preventing orphaned key-store entries on invalid input.
- Hardened bundle parsing: strict integer version validation and rejection of empty or unexpected key identifiers.
- Made key-store permission handling conditional on POSIX, improving portability.
- Removed an unreachable XOR key-length check and expanded the test suite.

## License

MIT. See [LICENSE](LICENSE).
