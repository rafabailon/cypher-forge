"""Interactive and scriptable command-line interface for Cipher Forge."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from . import __version__
from .engine import CipherEngine
from .errors import CipherForgeError, FileAccessError, InvalidBundleError
from .keystore import KeyStore
from .models import CipherBundle, LayerName

APP_NAME = "Cipher Forge"
KEY_STORE_ENV = "CIPHERFORGE_KEY_STORE"


def default_key_store_path() -> Path:
    configured = os.environ.get(KEY_STORE_ENV)
    if configured:
        return Path(configured).expanduser()
    config_root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return config_root / "cipherforge" / "keys.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipherforge",
        description="Compose reversible cipher layers into authenticated JSON bundles.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    layers = subparsers.add_parser(
        "layers", help="List available cipher layers and their properties."
    )
    layers.set_defaults(handler=_layers_command)

    encrypt = subparsers.add_parser("encrypt", help="Encrypt a message into a JSON bundle.")
    encrypt.add_argument(
        "--layers",
        "-l",
        required=True,
        metavar="LIST",
        help="Comma-separated layer order, applied left to right.",
    )
    source = encrypt.add_mutually_exclusive_group()
    source.add_argument(
        "--message",
        "-m",
        help="Message text. Prefer --input or stdin to keep text out of shell history.",
    )
    source.add_argument(
        "--input",
        "-i",
        metavar="FILE",
        help="Read the message from FILE, or - for stdin.",
    )
    encrypt.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write the bundle to FILE, or - for stdout.",
    )
    encrypt.set_defaults(handler=_encrypt_command)

    decrypt = subparsers.add_parser("decrypt", help="Decrypt a JSON bundle.")
    decrypt.add_argument(
        "bundle",
        nargs="?",
        metavar="FILE",
        help="Bundle file, or - for stdin. Defaults to stdin.",
    )
    decrypt.set_defaults(handler=_decrypt_command)

    verify = subparsers.add_parser("verify", help="Verify a bundle's HMAC integrity tag.")
    verify.add_argument(
        "bundle",
        nargs="?",
        metavar="FILE",
        help="Bundle file, or - for stdin. Defaults to stdin.",
    )
    verify.set_defaults(handler=_verify_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        engine = CipherEngine(KeyStore(default_key_store_path()))
    except CipherForgeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if args.command is None:
        return _interactive_menu(engine)

    handler: Callable[[CipherEngine, argparse.Namespace], int] = args.handler
    try:
        return handler(engine, args)
    except CipherForgeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130


def _interactive_menu(engine: CipherEngine) -> int:
    actions: dict[str, Callable[[], None]] = {
        "1": lambda: _interactive_encrypt(engine),
        "2": lambda: _interactive_decrypt(engine),
        "3": lambda: _interactive_verify(engine),
    }
    while True:
        print(f"\n{APP_NAME} — Multi-Layer Cipher Engine")
        print("1. Encrypt a message")
        print("2. Decrypt a bundle")
        print("3. Verify bundle integrity")
        print("4. Exit")
        try:
            choice = input("Choose an option: ").strip()
        except EOFError:
            print("\nGoodbye.")
            return 0
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 130
        if choice == "4":
            return 0
        action = actions.get(choice)
        if action is None:
            print("Choose 1, 2, 3, or 4.")
            continue
        try:
            action()
        except CipherForgeError as error:
            print(f"Error: {error}")
        except EOFError:
            print("\nGoodbye.")
            return 0
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 130


def _interactive_encrypt(engine: CipherEngine) -> None:
    message = input("Message to encrypt: ")
    choices = ", ".join(layer.value for layer in LayerName)
    print(f"Available layers: {choices}")
    layers = _parse_layers(input("Layer order, outermost last (comma-separated): "))
    bundle = engine.encrypt(message, layers)
    print("\nEncrypted bundle (save it to decrypt later):")
    print(bundle.to_json())
    print(f"\nKeys are stored locally at: {engine.key_store.path}")


def _interactive_decrypt(engine: CipherEngine) -> None:
    print(f"Decrypted message: {engine.decrypt(_prompt_bundle())}")


def _interactive_verify(engine: CipherEngine) -> None:
    engine.verify(_prompt_bundle())
    print("Bundle integrity verified.")


def _prompt_bundle() -> CipherBundle:
    return _read_bundle_source(input("Bundle file path or one-line JSON: "))


def _parse_layers(raw: str) -> tuple[LayerName, ...]:
    names = [item.strip().lower() for item in raw.split(",") if item.strip()]
    if not names:
        raise InvalidBundleError("Choose at least one cipher layer.")
    try:
        return tuple(LayerName(name) for name in names)
    except ValueError as error:
        choices = ", ".join(layer.value for layer in LayerName)
        raise InvalidBundleError(f"Unknown cipher layer. Choose from: {choices}.") from error


def _read_message(args: argparse.Namespace, stdin: TextIO | None = None) -> str:
    stream = stdin if stdin is not None else sys.stdin
    if args.message is not None:
        return args.message
    if args.input is not None:
        if args.input == "-":
            return stream.read()
        return _read_text_file(Path(args.input).expanduser(), "message")
    if stream.isatty():
        return input("Message to encrypt: ")
    return stream.read()


def _read_bundle_source(source: str | None, stdin: TextIO | None = None) -> CipherBundle:
    stream = stdin if stdin is not None else sys.stdin
    if source is None:
        if stream.isatty():
            source = input("Bundle file path or one-line JSON: ")
        else:
            return CipherBundle.from_json(stream.read())
    source = source.strip()
    if not source:
        raise InvalidBundleError("No bundle was supplied.")
    if source == "-":
        return CipherBundle.from_json(stream.read())
    if source.startswith("{"):
        return CipherBundle.from_json(source)
    return CipherBundle.from_json(_read_text_file(Path(source).expanduser(), "bundle"))


def _read_text_file(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise FileAccessError(f"Cannot read {label} file: {path}.") from error


def _encrypt_command(engine: CipherEngine, args: argparse.Namespace) -> int:
    message = _read_message(args)
    bundle = engine.encrypt(message, _parse_layers(args.layers))
    serialized = bundle.to_json() + "\n"
    if args.output and args.output != "-":
        path = Path(args.output).expanduser()
        try:
            path.write_text(serialized, encoding="utf-8")
        except OSError as error:
            raise FileAccessError(f"Cannot write bundle file: {path}.") from error
        print(f"Bundle written to {path}", file=sys.stderr)
    else:
        sys.stdout.write(serialized)
    print(f"Keys stored in {engine.key_store.path}", file=sys.stderr)
    return 0


def _decrypt_command(engine: CipherEngine, args: argparse.Namespace) -> int:
    print(engine.decrypt(_read_bundle_source(args.bundle)))
    return 0


def _verify_command(engine: CipherEngine, args: argparse.Namespace) -> int:
    engine.verify(_read_bundle_source(args.bundle))
    print("Bundle integrity verified.")
    return 0


def _layers_command(engine: CipherEngine, args: argparse.Namespace) -> int:  # noqa: ARG001
    from .layers import LAYERS

    print("Available layers:")
    for layer_name in LayerName:
        layer = LAYERS[layer_name]
        key_info = "requires key" if layer.requires_key else "no key required"
        print(f"  - {layer_name.value}: {key_info}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
