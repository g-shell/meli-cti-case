from datetime import datetime, timezone

from app.models import (
    FamilyCandidate,
    LLMAnalysis,
    Observable,
    ProviderResult,
    TriageResult,
    TTPAssessment,
)
from app.services.storage import TriageRepository


def build_result(
    scan_id: str = "scan-1",
    observable_value: str = "observed.test",
) -> TriageResult:
    return TriageResult(
        scan_id=scan_id,
        requested_hash="a" * 64,
        hash_type="sha256",
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        status="completed",
        providers=[
            ProviderResult(
                provider="virustotal",
                status="ok",
            )
        ],
        observables=[
            Observable(
                type="domain",
                value=observable_value,
                source="virustotal",
                relationship="sandbox_dns",
                confidence="medium",
            )
        ],
        analysis=LLMAnalysis(
            verdict="malicious",
            confidence="high",
            executive_summary=(
                "Resultado sintético para teste."
            ),
            family_candidates=[
                FamilyCandidate(
                    family="testfamily",
                    confidence="medium",
                    supporting_evidence_ids=[
                        "E001"
                    ],
                    rationale=(
                        "Família utilizada no teste."
                    ),
                )
            ],
            ttps=[
                TTPAssessment(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    confidence="high",
                    evidence_ids=["E002"],
                    rationale=(
                        "Comando observado."
                    ),
                )
            ],
        ),
    )


def test_repository_round_trip_and_history(
    tmp_path,
):
    database_path = tmp_path / "cti.db"
    csv_path = tmp_path / "history.csv"

    repository = TriageRepository(
        database_path,
        csv_path,
    )

    original = build_result()

    repository.save(original)

    loaded = repository.get(
        original.scan_id
    )

    assert loaded is not None
    assert loaded.scan_id == original.scan_id
    assert (
        loaded.requested_hash
        == original.requested_hash
    )

    assert loaded.analysis is not None
    assert loaded.analysis.verdict == "malicious"

    history = repository.list()

    assert len(history) == 1
    assert history[0].scan_id == original.scan_id

    filtered = repository.list(
        artifact_hash="a" * 64
    )

    assert len(filtered) == 1

    latest = repository.get_latest_for_hash(
        "a" * 64
    )

    assert latest is not None
    assert latest.scan_id == original.scan_id

    assert database_path.exists()
    assert csv_path.exists()

    csv_content = csv_path.read_text(
        encoding="utf-8"
    )

    assert "requested_hash" in csv_content
    assert original.scan_id in csv_content


def test_export_scan_csv(
    tmp_path,
):
    repository = TriageRepository(
        tmp_path / "cti.db",
        tmp_path / "history.csv",
    )

    result = build_result(
        scan_id="scan-export"
    )

    repository.save(result)

    exported = repository.export_scan_csv(
        "scan-export"
    )

    assert exported is not None
    assert "observed.test" in exported
    assert "testfamily" in exported
    assert "T1059.001" in exported
    assert "PowerShell" in exported

    assert (
        repository.export_scan_csv(
            "missing"
        )
        is None
    )


def test_csv_formula_injection_is_neutralized(
    tmp_path,
):
    repository = TriageRepository(
        tmp_path / "cti.db",
        tmp_path / "history.csv",
    )

    malicious_value = (
        '=HYPERLINK("https://example.test")'
    )

    result = build_result(
        scan_id="scan-csv-security",
        observable_value=malicious_value,
    )

    repository.save(result)

    exported = repository.export_scan_csv(
        result.scan_id
    )

    assert exported is not None

    # A apóstrofe impede a execução como fórmula.
    assert "'=HYPERLINK" in exported