import hashlib

from datetime import datetime, timezone

import pytest

from app.models import Evidence, Observable, TriageResult
from app.services.detection_rules import _quote, build_detection_rules
from app.services.report import build_cti_report


SAMPLE = b"cti-triage-detection-rule-test"
SAMPLE_SHA256 = hashlib.sha256(SAMPLE).hexdigest()
DROPPED = "e" * 64
PARENT = "b" * 64


def macos_result() -> TriageResult:
    return TriageResult(
        scan_id="33333333-3333-4333-8333-333333333333",
        requested_hash=SAMPLE_SHA256,
        hash_type="sha256",
        created_at=datetime.now(timezone.utc),
        status="completed",
        observables=[
            Observable(type="hash", value=DROPPED, source="virustotal", relationship="dropped_files"),
            Observable(
                type="ip",
                value="17.253.7.201",
                source="virustotal",
                relationship="contacted_ips",
                context={"known_infrastructure": "Apple"},
            ),
            Observable(
                type="ip",
                value="203.0.113.10",
                source="virustotal",
                relationship="contacted_ips",
                context={"last_analysis_stats": {"malicious": 0}},
            ),
            Observable(type="domain", value="evil.example.test", source="virustotal"),
        ],
        evidence=[
            Evidence(
                id="E001",
                source="virustotal",
                kind="file_metadata",
                value={"sha256": SAMPLE_SHA256, "md5": "a" * 32, "type_description": "Mach-O"},
            ),
            Evidence(
                id="E002",
                source="virustotal",
                kind="sandbox_command",
                value="sh -c killall Terminal",
            ),
            Evidence(
                id="E003",
                source="virustotal",
                kind="sandbox_command",
                value="launchctl load /Users/u/Library/LaunchAgents/com.u.gfskjsnghdjsvuxj.plist",
            ),
            Evidence(
                id="E004",
                source="virustotal",
                kind="file_written",
                value="/private/var/root/Library/LaunchAgents/com.root.gfskjsnghdjsvuxj.plist",
            ),
            # Ruído de sandbox Windows: não pode gerar regras de Windows.
            Evidence(
                id="E005",
                source="virustotal",
                kind="sandbox_command",
                value="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAAA",
            ),
            Evidence(
                id="E006",
                source="malwarebazaar",
                kind="related_family_label",
                value={"relation": "dropped_by", "sha256": PARENT, "label": "AMOS"},
            ),
        ],
    )


def windows_result() -> TriageResult:
    return TriageResult(
        scan_id="44444444-4444-4444-8444-444444444444",
        requested_hash="c" * 64,
        hash_type="sha256",
        created_at=datetime.now(timezone.utc),
        status="completed",
        evidence=[
            Evidence(
                id="E001",
                source="virustotal",
                kind="file_metadata",
                value={"sha256": "c" * 64, "type_description": "Win32 EXE"},
            ),
            Evidence(
                id="E002",
                source="virustotal",
                kind="sandbox_command",
                value="powershell.exe -NoP -enc SQBFAFgA",
            ),
            Evidence(
                id="E003",
                source="virustotal",
                kind="registry_key_set",
                value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            ),
        ],
    )


def _rules(result: TriageResult):
    return build_cti_report(result).detection_rules


def test_ioc_rules_cover_chain_hashes_and_actionable_network() -> None:
    rules = {rule.language + ":" + rule.basis: rule for rule in _rules(macos_result())}

    yara_rule = rules["yara:ioc"].content
    for value in (SAMPLE_SHA256, DROPPED, PARENT):
        assert value in yara_rule

    kql = rules["kql:ioc"].content
    assert "203.0.113.10" in kql
    assert "evil.example.test" in kql
    # Infraestrutura de SO/CDN nunca entra em regra.
    assert "17.253.7.201" not in kql
    assert "correlação, não para bloqueio" in rules["kql:ioc"].rationale


def test_behavior_rules_only_for_artifact_platform() -> None:
    rules = _rules(macos_result())
    titles = " ".join(rule.title for rule in rules)

    assert "LaunchAgent" in titles
    assert "launchctl" in titles
    assert "Terminal" in titles
    # O PowerShell veio da sandbox Windows: não vira regra para um Mach-O.
    assert "PowerShell" not in titles

    launch = next(rule for rule in rules if rule.language == "eql" and "criação" in rule.title)
    assert "[a-z]{16}" in launch.content
    assert launch.mitre_attack == ["T1543.001"]
    assert set(launch.evidence_ids) == {"E003", "E004"}


def test_windows_behavior_rules() -> None:
    rules = _rules(windows_result())
    titles = [rule.title for rule in rules]

    assert any("PowerShell" in title for title in titles)
    run_key = next(rule for rule in rules if "Run" in rule.title)
    assert '"Updater"' in run_key.content
    assert not any("LaunchAgent" in title for title in titles)


def test_no_rules_without_data() -> None:
    result = TriageResult(
        scan_id="55555555-5555-4555-8555-555555555555",
        requested_hash="not-a-sha256-hash",
        hash_type="sha256",
        created_at=datetime.now(timezone.utc),
        status="failed",
    )

    assert _rules(result) == []


def test_quote_escapes_rule_syntax() -> None:
    assert _quote('a"b\\c\n') == '"a\\"b\\\\c"'


def test_generated_yara_compiles_and_matches() -> None:
    yara = pytest.importorskip("yara")

    rule = next(item for item in _rules(macos_result()) if item.language == "yara")
    compiled = yara.compile(source=rule.content)

    assert compiled.match(data=SAMPLE)
    assert not compiled.match(data=b"outro arquivo")


def test_generated_sigma_parses_and_converts_to_elastic() -> None:
    collection = pytest.importorskip("sigma.collection")
    backends = pytest.importorskip("sigma.backends.elasticsearch")

    sigma_rules = [item for item in _rules(macos_result()) if item.language == "sigma"]
    assert len(sigma_rules) == 2

    for item in sigma_rules:
        parsed = collection.SigmaCollection.from_yaml(item.content)
        assert not parsed.rules[0].errors
        assert backends.LuceneBackend().convert(parsed)
