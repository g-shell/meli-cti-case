from app.models import ProviderResult
from app.services.normalize import (
    family_consensus,
    normalize_providers,
)


def provider_fixtures() -> list[ProviderResult]:
    vt_result = ProviderResult(
        provider="virustotal",
        status="ok",
        data={
            "report": {
                "data": {
                    "type": "file",
                    "id": "a" * 64,
                    "attributes": {
                        "sha256": "a" * 64,
                        "sha1": "c" * 40,
                        "md5": "b" * 32,
                        "size": 1234,
                        "type_description": "Win32 EXE",
                        "names": [
                            "invoice.exe",
                        ],
                        "tags": [
                            "peexe",
                        ],
                        "last_analysis_stats": {
                            "malicious": 42,
                            "suspicious": 2,
                            "undetected": 20,
                        },
                        "popular_threat_classification": {
                            "suggested_threat_label": (
                                "trojan.emotet"
                            )
                        },
                    },
                }
            },
            "related": {
                "contacted_ips": {
                    "available": True,
                    "payload": {
                        "data": [
                            {
                                "id": "198.51.100.10",
                                "attributes": {
                                    "last_analysis_stats": {
                                        "malicious": 4,
                                    }
                                },
                            }
                        ]
                    },
                },
                "contacted_domains": {
                    "available": True,
                    "payload": {
                        "data": [
                            {
                                "id": "example.test",
                                "attributes": {},
                            }
                        ]
                    },
                },
                "contacted_urls": {
                    "available": True,
                    "payload": {
                        "data": [],
                    },
                },
                "dropped_files": {
                    "available": True,
                    "payload": {
                        "data": [],
                    },
                },
                "behaviour_summary": {
                    "available": True,
                    "payload": {
                        "data": {
                            "command_executions": [
                                "powershell.exe -enc AAAA",
                            ],
                            "files_written": [
                                (
                                    "C:\\Users\\Public\\"
                                    "stage.dll"
                                )
                            ],
                            "registry_keys_set": [
                                (
                                    "HKCU\\Software\\Microsoft\\"
                                    "Windows\\CurrentVersion\\"
                                    "Run\\Updater"
                                )
                            ],
                            "dns_lookups": [
                                {
                                    "hostname": "example.test",
                                }
                            ],
                        }
                    },
                },
            },
        },
    )

    mb_result = ProviderResult(
        provider="malwarebazaar",
        status="ok",
        data={
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "file_name": "invoice.exe",
                    "file_type": "exe",
                    "signature": "Emotet",
                    "tags": [
                        "exe",
                    ],
                }
            ],
        },
    )

    return [
        vt_result,
        mb_result,
    ]


def test_normalizes_observables_and_evidence():
    providers = provider_fixtures()

    observables, evidence, features = (
        normalize_providers(
            providers
        )
    )

    assert any(
        observable.type == "ip"
        and observable.value == "198.51.100.10"
        for observable in observables
    )

    assert any(
        observable.type == "domain"
        and observable.value == "example.test"
        for observable in observables
    )

    # O mesmo domínio aparece no relacionamento
    # e no sandbox, mas deve existir uma vez.
    assert len(
        [
            observable
            for observable in observables
            if observable.value == "example.test"
        ]
    ) == 1

    assert evidence

    expected_ids = [
        f"E{index:03d}"
        for index in range(
            1,
            len(evidence) + 1,
        )
    ]

    assert [
        item.id
        for item in evidence
    ] == expected_ids

    assert features["commands"]

    assert (
        features["commands"][0]["value"]
        == "powershell.exe -enc AAAA"
    )


def test_creates_high_confidence_family_consensus():
    providers = provider_fixtures()

    _, _, features = normalize_providers(
        providers
    )

    candidates = family_consensus(
        features
    )

    assert candidates

    assert (
        candidates[0]["family"]
        == "emotet"
    )

    assert (
        candidates[0]["confidence"]
        == "high"
    )

    assert (
        candidates[0]["independent_sources"]
        == 2
    )


def test_ignores_unavailable_enrichment():
    vt_result = ProviderResult(
        provider="virustotal",
        status="ok",
        data={
            "report": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                        }
                    }
                }
            },
            "related": {
                "contacted_ips": {
                    "available": False,
                    "http_status": 403,
                    "error": "http_error",
                },
                "behaviour_summary": {
                    "available": False,
                    "http_status": 429,
                    "error": "http_error",
                },
            },
        },
    )

    observables, evidence, features = (
        normalize_providers(
            [
                vt_result,
            ]
        )
    )

    assert observables == []
    assert evidence
    assert features["commands"] == []


def test_records_failed_provider_as_evidence():
    mb_result = ProviderResult(
        provider="malwarebazaar",
        status="not_found",
    )

    observables, evidence, features = (
        normalize_providers(
            [
                mb_result,
            ]
        )
    )

    assert observables == []

    assert any(
        item.kind == "source_status"
        and item.source == "malwarebazaar"
        for item in evidence
    )

    assert features["family_signals"] == []