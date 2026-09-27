from app.models import (
    Evidence,
    Observable,
    ProviderResult,
)
from app.services.deterministic import (
    build_deterministic_analysis,
)


def test_malicious_sample_maps_observed_behaviors():
    providers = [
        ProviderResult(
            provider="virustotal",
            status="ok",
        ),
        ProviderResult(
            provider="malwarebazaar",
            status="ok",
        ),
    ]

    evidence = [
        Evidence(
            id="E001",
            source="virustotal",
            kind="detection_stats",
            value={
                "malicious": 33,
                "suspicious": 0,
                "undetected": 30,
            },
        ),
        Evidence(
            id="E002",
            source="virustotal",
            kind="popular_threat_classification",
            value={
                "suggested_threat_label": "trojan.emotet",
            },
        ),
        Evidence(
            id="E003",
            source="malwarebazaar",
            kind="signature",
            value="Emotet",
        ),
        Evidence(
            id="E004",
            source="virustotal",
            kind="sandbox_command",
            value="powershell.exe -enc AAAA",
        ),
        Evidence(
            id="E005",
            source="virustotal",
            kind="sandbox_command",
            value="rundll32.exe stage.dll,Start",
        ),
        Evidence(
            id="E006",
            source="virustotal",
            kind="registry_key_set",
            value=(
                "HKCU\\Software\\Microsoft\\Windows\\"
                "CurrentVersion\\Run\\Updater"
            ),
        ),
    ]

    observables = [
        Observable(
            type="domain",
            value="example.test",
            source="virustotal",
            relationship="sandbox_dns",
            confidence="high",
        )
    ]

    features = {
        "family_signals": [
            {
                "family": "trojan.emotet",
                "source": "virustotal",
                "evidence_id": "E002",
            },
            {
                "family": "Emotet",
                "source": "malwarebazaar",
                "evidence_id": "E003",
            },
        ],
        "commands": [
            {
                "value": "powershell.exe -enc AAAA",
                "evidence_id": "E004",
            },
            {
                "value": "rundll32.exe stage.dll,Start",
                "evidence_id": "E005",
            },
        ],
        "registry_keys": [
            {
                "value": (
                    "HKCU\\Software\\Microsoft\\Windows\\"
                    "CurrentVersion\\Run\\Updater"
                ),
                "evidence_id": "E006",
            }
        ],
        "files_written": [],
    }

    analysis = build_deterministic_analysis(
        providers,
        observables,
        evidence,
        features,
    )

    assert analysis.verdict == "malicious"
    assert analysis.confidence == "high"

    technique_ids = {
        item.technique_id
        for item in analysis.ttps
    }

    assert "T1059.001" in technique_ids
    assert "T1218.011" in technique_ids
    assert "T1547.001" in technique_ids

    # Não existe evidência de credential dumping.
    assert "T1003" not in technique_ids

    powershell = next(
        item
        for item in analysis.ttps
        if item.technique_id == "T1059.001"
    )

    assert powershell.evidence_ids == ["E004"]

    assert analysis.family_candidates[0].family == "emotet"
    assert analysis.family_candidates[0].confidence == "high"

    assert analysis.c2_assessment[0].value == "example.test"
    assert analysis.c2_assessment[0].confidence == "medium"


def test_malicious_verdict_does_not_invent_ttps():
    providers = [
        ProviderResult(
            provider="virustotal",
            status="ok",
        )
    ]

    evidence = [
        Evidence(
            id="E001",
            source="virustotal",
            kind="detection_stats",
            value={
                "malicious": 20,
                "suspicious": 0,
            },
        )
    ]

    features = {
        "family_signals": [],
        "commands": [],
        "registry_keys": [],
        "files_written": [],
    }

    analysis = build_deterministic_analysis(
        providers,
        [],
        evidence,
        features,
    )

    assert analysis.verdict == "malicious"
    assert analysis.ttps == []


def test_missing_results_are_unknown_not_benign():
    providers = [
        ProviderResult(
            provider="virustotal",
            status="not_found",
        ),
        ProviderResult(
            provider="malwarebazaar",
            status="not_found",
        ),
    ]

    features = {
        "family_signals": [],
        "commands": [],
        "registry_keys": [],
        "files_written": [],
    }

    analysis = build_deterministic_analysis(
        providers,
        [],
        [],
        features,
    )

    assert analysis.verdict == "unknown"
    assert analysis.confidence == "low"
    assert analysis.verdict != "benign"


def test_malwarebazaar_only_is_suspicious():
    providers = [
        ProviderResult(
            provider="virustotal",
            status="not_found",
        ),
        ProviderResult(
            provider="malwarebazaar",
            status="ok",
        ),
    ]

    features = {
        "family_signals": [],
        "commands": [],
        "registry_keys": [],
        "files_written": [],
    }

    analysis = build_deterministic_analysis(
        providers,
        [],
        [],
        features,
    )

    assert analysis.verdict == "suspicious"
    assert analysis.confidence == "medium"