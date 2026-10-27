import io

import pytest

from cipherforge import cli


@pytest.fixture
def key_store_path(monkeypatch, tmp_path):
    path = tmp_path / "keys.json"
    monkeypatch.setenv(cli.KEY_STORE_ENV, str(path))
    return path


def test_cli_encrypt_verify_and_decrypt_round_trip(monkeypatch, key_store_path, capsys):
    answers = iter(["1", "A message for the CLI 🌙", "caesar,fernet,base64", "4"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    assert cli.main([]) == 0
    output = capsys.readouterr().out
    assert "Encrypted bundle" in output
    start = output.index('{\n  "version"')
    end = output.index("\n}", start) + 2
    bundle = output[start:end]

    answers = iter(["3", bundle, "2", bundle, "4"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    assert cli.main([]) == 0
    output = capsys.readouterr().out
    assert "Bundle integrity verified." in output
    assert "Decrypted message: A message for the CLI 🌙" in output


def test_cli_exits_cleanly(monkeypatch, key_store_path):
    monkeypatch.setattr("builtins.input", lambda _prompt: "4")
    assert cli.main([]) == 0


def test_cli_non_interactive_file_round_trip(key_store_path, tmp_path, capsys):
    message_file = tmp_path / "message.txt"
    message_file.write_text("Scriptable café 🌒", encoding="utf-8")
    bundle_file = tmp_path / "bundle.json"

    assert (
        cli.main(
            [
                "encrypt",
                "--layers",
                "caesar,vigenere,xor,fernet,base64",
                "--input",
                str(message_file),
                "--output",
                str(bundle_file),
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert "Bundle written to" in output.err
    assert "Keys stored in" in output.err

    assert cli.main(["verify", str(bundle_file)]) == 0
    assert "Bundle integrity verified." in capsys.readouterr().out

    assert cli.main(["decrypt", str(bundle_file)]) == 0
    assert capsys.readouterr().out.strip() == "Scriptable café 🌒"


def test_cli_reads_message_and_bundle_from_stdin(key_store_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("Piped message ✨"))
    assert cli.main(["encrypt", "--layers", "fernet,base64", "--input", "-"]) == 0
    bundle = capsys.readouterr().out
    assert '"version": 1' in bundle

    monkeypatch.setattr("sys.stdin", io.StringIO(bundle))
    assert cli.main(["verify"]) == 0
    assert "Bundle integrity verified." in capsys.readouterr().out

    monkeypatch.setattr("sys.stdin", io.StringIO(bundle))
    assert cli.main(["decrypt", "-"]) == 0
    assert capsys.readouterr().out.strip() == "Piped message ✨"


def test_cli_rejects_unknown_layer(key_store_path, capsys):
    assert cli.main(["encrypt", "--layers", "caesar,rot13", "--message", "text"]) == 1
    assert "Unknown cipher layer" in capsys.readouterr().err


def test_cli_reports_unreadable_bundle(key_store_path, tmp_path, capsys):
    missing = tmp_path / "missing.json"
    assert cli.main(["decrypt", str(missing)]) == 1
    assert f"Cannot read bundle file: {missing}." in capsys.readouterr().err


def test_cli_reports_unwritable_bundle_output(key_store_path, tmp_path, capsys):
    output = tmp_path / "missing-directory" / "bundle.json"
    result = cli.main(
        ["encrypt", "--layers", "base64", "--message", "text", "--output", str(output)]
    )
    assert result == 1
    assert f"Cannot write bundle file: {output}." in capsys.readouterr().err


def test_cli_version_option(key_store_path, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--version"])
    assert error.value.code == 0
    assert "Cipher Forge" in capsys.readouterr().out


def test_default_key_store_path_prefers_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(cli.KEY_STORE_ENV, str(tmp_path / "custom.json"))
    assert cli.default_key_store_path() == tmp_path / "custom.json"


def test_default_key_store_path_uses_xdg_config_home(monkeypatch, tmp_path):
    monkeypatch.delenv(cli.KEY_STORE_ENV, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert cli.default_key_store_path() == tmp_path / "cipherforge" / "keys.json"
