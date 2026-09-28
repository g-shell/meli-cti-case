import asyncio

from pathlib import Path

from app.config import Settings
from app.models import (
    Evidence,
    FamilyCandidate,
    LLMAnalysis,
    Observable,
    ProviderResult,
    TriageRequest,
    TTPAssessment,
)
from app.services.agent import (
    TriageState,
    TriageWorkflow,
)

from typing import Any

from app.services.storage import (
    TriageRepository,
)

class FakeClient:
    def __init__(
        self,
        result: ProviderResult,
    ) -> None:
        self.result = result

    async def lookup_hash(
        self,
        artifact_hash: str,
    ) -> ProviderResult:
        return self.result


def build_vt_result(
    malicious: int = 12,
) -> ProviderResult:
    return ProviderResult(
        provider="virustotal",
        status="ok",
        data={
            "report": {
                "data": {
                    "id": "a" * 64,
                    "attributes": {
                        "sha256": "a" * 64,
                        "size": 1234,
                        "type_description": (
                            "Win32 EXE"
                        ),
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": 0,
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
            "related": {},
        },
    )


def build_mb_result() -> ProviderResult:
    return ProviderResult(
        provider="malwarebazaar",
        status="ok",
        data={
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "file_name": "sample.exe",
                    "file_type": "exe",
                    "signature": "Emotet",
                    "tags": ["exe"],
                }
            ],
        },
    )


def test_workflow_uses_deterministic_fallback(
    tmp_path: Path,
) -> None:
    settings = Settings(
        enable_genai=False,
        openai_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=tmp_path / "history.csv",
    )

    workflow = TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            build_mb_result()
        ),
    )

    request = TriageRequest(
        hash="a" * 64,
        use_genai=False,
    )

    result = asyncio.run(
        workflow.run(request)
    )

    assert result.status == "completed"
    assert result.analysis is not None

    assert result.analysis.verdict == "malicious"
    assert result.analysis.confidence == "high"

    assert len(result.providers) == 2
    assert result.source_errors == []

    assert result.analysis.family_candidates

    assert (
        result.analysis.family_candidates[0].family
        == "emotet"
    )

    assert (
        result.analysis.family_candidates[0].confidence
        == "high"
    )

    # Confirma que o nó persist salvou no SQLite.
    stored = workflow.repository.get(
        result.scan_id
    )

    assert stored is not None
    assert stored.scan_id == result.scan_id
    assert (
        stored.requested_hash
        == result.requested_hash
    )

    assert stored.analysis is not None
    assert stored.analysis.verdict == "malicious"

    # Confirma a criação dos arquivos de persistência.
    assert settings.database_path.exists()
    assert settings.csv_export_path.exists()


def test_workflow_marks_partial_collection(
    tmp_path: Path,
) -> None:
    settings = Settings(
        enable_genai=False,
        openai_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=tmp_path / "history.csv",
    )

    malwarebazaar_error = ProviderResult(
        provider="malwarebazaar",
        status="rate_limited",
        error="MalwareBazaar HTTP 429",
    )

    workflow = TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            malwarebazaar_error
        ),
    )

    request = TriageRequest(
        hash="a" * 64,
        use_genai=False,
    )

    result = asyncio.run(
        workflow.run(request)
    )

    assert result.status == "partial"

    assert any(
        "malwarebazaar" in error.lower()
        for error in result.source_errors
    )

    # Resultados parciais também devem ser persistidos.
    stored = workflow.repository.get(
        result.scan_id
    )

    assert stored is not None
    assert stored.status == "partial"

    assert any(
        provider.provider == "malwarebazaar"
        and provider.status == "rate_limited"
        for provider in stored.providers
    )


def test_grounding_removes_unsupported_claims(
    tmp_path: Path,
) -> None:
    settings = Settings(
        enable_genai=False,
        openai_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=tmp_path / "history.csv",
    )

    workflow = TriageWorkflow(
        settings=settings,
    )

    observed_domain = Observable(
        type="domain",
        value="observed.test",
        source="virustotal",
        relationship="sandbox_dns",
        confidence="high",
    )

    baseline = LLMAnalysis(
        verdict="suspicious",
        confidence="medium",
        executive_summary=(
            "Baseline determinística."
        ),
    )

    generated = LLMAnalysis(
        verdict="malicious",
        confidence="high",
        executive_summary=(
            "Análise gerada para teste."
        ),
        family_candidates=[
            FamilyCandidate(
                family="supported",
                confidence="medium",
                supporting_evidence_ids=[
                    "E001"
                ],
                rationale=(
                    "Possui evidência válida."
                ),
            ),
            FamilyCandidate(
                family="invented",
                confidence="high",
                supporting_evidence_ids=[
                    "E999"
                ],
                rationale=(
                    "Evidência inexistente."
                ),
            ),
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
            ),
            TTPAssessment(
                technique_id="T1003",
                technique_name=(
                    "OS Credential Dumping"
                ),
                confidence="high",
                evidence_ids=["E001"],
                rationale=(
                    "Evidência inadequada."
                ),
            ),
        ],
        c2_assessment=[
            observed_domain,
            Observable(
                type="domain",
                value="invented.test",
                source="llm",
                confidence="high",
            ),
        ],
    )

    state: TriageState = {
        "analysis": generated,
        "deterministic_analysis": baseline,
        "evidence": [
            Evidence(
                id="E001",
                source="malwarebazaar",
                kind="signature",
                value="supported",
            ),
            Evidence(
                id="E002",
                source="virustotal",
                kind="sandbox_command",
                value="powershell.exe -enc AAAA",
            ),
        ],
        "observables": [
            observed_domain
        ],
    }

    grounded_result = asyncio.run(
        workflow._ground(state)
    )

    grounded = grounded_result["analysis"]

    assert [
        item.family
        for item in grounded.family_candidates
    ] == ["supported"]

    assert [
        item.technique_id
        for item in grounded.ttps
    ] == ["T1059.001"]

    assert [
        item.value
        for item in grounded.c2_assessment
    ] == ["observed.test"]

    assert (
        grounded.c2_assessment[0].confidence
        == "medium"
    )


def test_grounding_drops_cross_platform_noise(
    tmp_path: Path,
) -> None:
    """
    Reproduz o scan real: Mach-O aberto numa sandbox Windows
    e tráfego para Apple/Fastly.
    """
    settings = Settings(
        enable_genai=False,
        openai_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=tmp_path / "history.csv",
    )

    workflow = TriageWorkflow(
        settings=settings,
    )

    apple_ip = Observable(
        type="ip",
        value="17.253.7.201",
        source="virustotal",
        relationship="contacted_ips",
        context={
            "known_infrastructure": "Apple",
            "last_analysis_stats": {"malicious": 0},
        },
    )
    cloud_ip = Observable(
        type="ip",
        value="54.173.154.19",
        source="virustotal",
        relationship="contacted_ips",
        context={
            "last_analysis_stats": {"malicious": 0},
        },
    )

    generated = LLMAnalysis(
        verdict="malicious",
        confidence="high",
        executive_summary="Teste.",
        ttps=[
            TTPAssessment(
                technique_id="T1543.001",
                technique_name="Launch Agent",
                confidence="high",
                evidence_ids=["E002"],
                rationale="launchctl load.",
            ),
            TTPAssessment(
                technique_id="T1218.011",
                technique_name="Rundll32",
                confidence="high",
                evidence_ids=["E003"],
                rationale="Ruído de sandbox Windows.",
            ),
        ],
        c2_assessment=[apple_ip, cloud_ip],
    )

    state: TriageState = {
        "analysis": generated,
        "deterministic_analysis": generated,
        "evidence": [
            Evidence(
                id="E001",
                source="virustotal",
                kind="file_metadata",
                value={"type_description": "Mach-O"},
            ),
            Evidence(
                id="E002",
                source="virustotal",
                kind="sandbox_command",
                value=(
                    "launchctl load /Users/u/Library/"
                    "LaunchAgents/com.root.x.plist"
                ),
            ),
            Evidence(
                id="E003",
                source="virustotal",
                kind="sandbox_command",
                value=(
                    '"C:\\Windows\\system32\\rundll32.exe" '
                    "shell32.dll,OpenAs_RunDLL"
                ),
            ),
        ],
        "observables": [apple_ip, cloud_ip],
    }

    grounded = asyncio.run(
        workflow._ground(state)
    )["analysis"]

    assert [
        item.technique_id
        for item in grounded.ttps
    ] == ["T1543.001"]

    assert [
        (item.value, item.confidence)
        for item in grounded.c2_assessment
    ] == [("54.173.154.19", "low")]

    caveats = " ".join(grounded.analytic_caveats)
    assert "T1218.011" in caveats
    assert "17.253.7.201" in caveats


class FakeRawMessage:
    def __init__(self) -> None:
        self.usage_metadata = {
            "input_tokens": 120,
            "output_tokens": 30,
            "total_tokens": 150,
        }


class FakeGenAIModel:
    def __init__(self) -> None:
        self.calls = 0
        self.last_input: Any = None

    async def ainvoke(
        self,
        model_input: Any,
    ) -> dict[str, Any]:
        self.calls += 1
        self.last_input = model_input

        return {
            "raw": FakeRawMessage(),
            "parsed": LLMAnalysis(
                verdict="malicious",
                confidence="high",
                executive_summary=(
                    "MOCK_GENAI_EXECUTED"
                ),
            ),
            "parsing_error": None,
        }


class FailingGenAIModel:
    def __init__(self) -> None:
        self.calls = 0

    async def ainvoke(
        self,
        model_input: Any,
    ) -> Any:
        self.calls += 1

        raise RuntimeError(
            "Falha simulada da GenAI."
        )


def test_genai_mock_records_usage(
    tmp_path: Path,
) -> None:
    settings = Settings(
        enable_genai=True,
        genai_provider="anthropic",
        anthropic_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=(
            tmp_path / "history.csv"
        ),
    )

    repository = TriageRepository(
        database_path=settings.database_path,
        csv_path=settings.csv_export_path,
    )

    fake_model = FakeGenAIModel()

    workflow = TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            build_mb_result()
        ),
        repository=repository,
        analysis_model=fake_model,
    )

    request = TriageRequest(
        hash="a" * 64,
        use_genai=True,
    )

    result = asyncio.run(
        workflow.run(request)
    )

    assert fake_model.calls == 1
    assert result.source_errors == []

    execution = result.analysis_execution

    assert execution.requested is True
    assert execution.attempted is True
    assert execution.succeeded is True
    assert execution.engine == "genai"
    assert execution.provider == "anthropic"
    assert execution.fallback_used is False

    assert execution.usage.input_tokens == 120
    assert execution.usage.output_tokens == 30
    assert execution.usage.total_tokens == 150

    assert result.analysis is not None
    assert (
        result.analysis.executive_summary
        == "MOCK_GENAI_EXECUTED"
    )

    saved = repository.get(
        result.scan_id
    )

    assert saved is not None
    assert (
        saved.analysis_execution
        .usage.total_tokens
        == 150
    )


def test_use_genai_false_skips_model(
    tmp_path: Path,
) -> None:
    settings = Settings(
        enable_genai=True,
        genai_provider="anthropic",
        anthropic_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=(
            tmp_path / "history.csv"
        ),
    )

    fake_model = FakeGenAIModel()

    workflow = TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            build_mb_result()
        ),
        analysis_model=fake_model,
    )

    result = asyncio.run(
        workflow.run(
            TriageRequest(
                hash="a" * 64,
                use_genai=False,
            )
        )
    )

    assert fake_model.calls == 0

    execution = result.analysis_execution

    assert execution.requested is False
    assert execution.attempted is False
    assert execution.succeeded is False
    assert execution.engine == "deterministic"
    assert execution.usage.total_tokens == 0


def test_genai_failure_uses_fallback(
    tmp_path: Path,
) -> None:
    settings = Settings(
        enable_genai=True,
        genai_provider="anthropic",
        anthropic_api_key=None,
        database_path=tmp_path / "cti.db",
        csv_export_path=(
            tmp_path / "history.csv"
        ),
    )

    failing_model = FailingGenAIModel()

    workflow = TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            build_mb_result()
        ),
        analysis_model=failing_model,
    )

    result = asyncio.run(
        workflow.run(
            TriageRequest(
                hash="a" * 64,
                use_genai=True,
            )
        )
    )

    assert failing_model.calls == 1

    execution = result.analysis_execution

    assert execution.requested is True
    assert execution.attempted is True
    assert execution.succeeded is False

    assert (
        execution.engine
        == "deterministic_fallback"
    )

    assert execution.fallback_used is True
    assert execution.usage.total_tokens == 0

    assert any(
        "GenAI indisponível" in error
        for error in result.source_errors
    )

    assert result.analysis is not None
    assert (
        result.analysis.verdict
        == "malicious"
    )