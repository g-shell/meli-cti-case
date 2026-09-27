from datetime import datetime, timezone

from app.models import (
    Evidence,
    FamilyCandidate,
    LLMAnalysis,
    Observable,
    ProviderResult,
    Recommendation,
    TriageResult,
    TTPAssessment,
)
from app.services.report import (
    build_cti_report,
    render_cti_report_html,
)


def build_result() -> TriageResult:
    observed_domain = Observable(
        type="domain",
        value="c2.example.test",
        source="virustotal",
        relationship="sandbox_dns",
        confidence="high",
        context={"evidence_id": "E004"},
    )

    return TriageResult(
        scan_id="11111111-1111-4111-8111-111111111111",
        requested_hash="a" * 64,
        hash_type="sha256",
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        status="completed",
        providers=[
            ProviderResult(
                provider="virustotal",
                status="ok",
            ),
            ProviderResult(
                provider="malwarebazaar",
                status="ok",
            ),
        ],
        observables=[observed_domain],
        evidence=[
            Evidence(
                id="E001",
                source="virustotal",
                kind="detection_stats",
                value={"malicious": 20},
            ),
            Evidence(
                id="E002",
                source="malwarebazaar",
                kind="signature",
                value="Emotet",
            ),
            Evidence(
                id="E003",
                source="virustotal",
                kind="sandbox_command",
                value="powershell.exe -enc AAAA",
            ),
            Evidence(
                id="E004",
                source="virustotal",
                kind="observable_sandbox_dns",
                value={
                    "type": "domain",
                    "value": "c2.example.test",
                },
            ),
            Evidence(
                id="E005",
                source="virustotal",
                kind="file_metadata",
                value={
                    "sha256": "a" * 64,
                    "size": 4096,
                    "type_description": "Win32 EXE",
                    "names": [
                        "sample.exe",
                        "<script>alert(1)</script>.exe",
                    ],
                    "tags": ["exe", "persistence"],
                },
            ),
        ],
        analysis=LLMAnalysis(
            verdict="malicious",
            confidence="high",
            executive_summary="Amostra maliciosa para teste.",
            family_candidates=[
                FamilyCandidate(
                    family="emotet",
                    confidence="high",
                    supporting_evidence_ids=["E002"],
                    rationale="Assinatura observada.",
                ),
                FamilyCandidate(
                    family="invented",
                    confidence="high",
                    supporting_evidence_ids=["E999"],
                    rationale="Evidência inexistente.",
                ),
            ],
            ttps=[
                TTPAssessment(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    confidence="high",
                    evidence_ids=["E003"],
                    rationale="Comando observado.",
                ),
                TTPAssessment(
                    technique_id="T1003",
                    technique_name="OS Credential Dumping",
                    confidence="high",
                    evidence_ids=["E999"],
                    rationale="Evidência inexistente.",
                ),
            ],
            c2_assessment=[
                observed_domain,
                Observable(
                    type="domain",
                    value="invented.example.test",
                    source="llm",
                    confidence="high",
                ),
            ],
            hunting_hypotheses=[
                "A amostra pode ter sido entregue por download."
            ],
            recommendations=[
                Recommendation(
                    priority="P0",
                    phase="containment",
                    action="Isolar o endpoint.",
                    rationale="Reduz exposição.",
                    d3fend_id="D3-NI",
                    validation="Confirmar isolamento no EDR.",
                )
            ],
        ),
        methodology=["Teste sintético."],
    )


def test_report_filters_unsupported_claims() -> None:
    report = build_cti_report(build_result())

    assert report.verdict == "malicious"
    assert [
        candidate.family
        for candidate in report.family_candidates
    ] == ["emotet"]
    assert [
        ttp.technique_id
        for ttp in report.ttps
    ] == ["T1059.001"]

    assert len(report.infrastructure) == 1
    assert (
        report.infrastructure[0].classification
        == "candidate_c2"
    )
    assert all(
        item.classification != "confirmed_c2"
        for item in report.infrastructure
    )


def test_report_contains_pirs_and_hunting_guidance() -> None:
    report = build_cti_report(build_result())

    assert len(report.intelligence_requirements) == 5
    assert (
        report.intelligence_requirements[0].pir_id
        == "PIR-001"
    )
    assert report.hunting_checklist
    assert any(
        item.data_source == "Windows forensic artifacts"
        for item in report.hunting_checklist
    )
    assert any(
        recommendation.d3fend_id == "D3-NI"
        for recommendation in report.recommendations
    )


def test_html_escapes_untrusted_values() -> None:
    report = build_cti_report(build_result())
    html = render_cti_report_html(report)

    assert "Relatório de Inteligência de Ameaças" in html
    assert "<script>alert(1)</script>.exe" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.exe" in html


def test_report_without_analysis_is_safe() -> None:
    result = build_result().model_copy(
        update={"analysis": None}
    )
    report = build_cti_report(result)

    assert report.verdict == "unknown"
    assert report.confidence == "low"
    assert report.family_candidates == []
    assert report.recommendations == []
