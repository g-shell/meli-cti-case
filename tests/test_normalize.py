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

def test_chain_signals_are_graded_below_sample_labels():
    """
    Reproduz o caso: amostra rotulada stealer/phebot, payload
    dropado rotulado macsync/phebot e pai rotulado AMOS.
    """
    vt_result = ProviderResult(
        provider="virustotal",
        status="ok",
        data={
            "report": {
                "data": {
                    "id": "a" * 64,
                    "attributes": {
                        "type_description": "Mach-O",
                        "last_analysis_stats": {"malicious": 33},
                        "popular_threat_classification": {
                            "suggested_threat_label": (
                                "trojan.stealer/phebot"
                            ),
                        },
                    },
                }
            },
            "related": {
                "dropped_files": {
                    "available": True,
                    "payload": {
                        "data": [
                            {
                                "id": "e" * 64,
                                "attributes": {
                                    "popular_threat_classification": {
                                        "suggested_threat_label": (
                                            "trojan.macsync/phebot"
                                        ),
                                    },
                                },
                            }
                        ]
                    },
                }
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
                    "signature": None,
                    "tags": ["macho"],
                }
            ],
            "related": {
                "dropped_by": {
                    "available": True,
                    "sha256": "b" * 64,
                    "sample": {
                        "signature": "AMOS",
                        "file_type": "sh",
                        "tags": ["AMOS", "sh"],
                    },
                }
            },
        },
    )

    _, evidence, features = normalize_providers(
        [vt_result, mb_result]
    )

    related = [
        item.value
        for item in evidence
        if item.kind == "related_family_label"
    ]
    assert {item["relation"] for item in related} == {
        "dropped_file",
        "dropped_by",
    }

    by_family = {
        item["family"]: item
        for item in family_consensus(features)
    }

    # Categorias funcionais não viram família.
    assert "stealer" not in by_family

    assert by_family["phebot"]["confidence"] == "medium"
    assert by_family["phebot"]["primary_sources"] == ["virustotal"]
    assert by_family["macsync"]["confidence"] == "low"
    assert by_family["amos"]["confidence"] == "low"
    assert by_family["amos"]["related_sources"] == ["malwarebazaar"]
