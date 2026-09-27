from __future__ import annotations

import asyncio

from pathlib import Path
from typing import Any

from app.config import Settings
from app.models import (
    LLMAnalysis,
    ProviderResult,
    TriageRequest,
)
from app.services.agent import (
    TriageWorkflow,
)
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


class FakeStructuredModel:
    """
    Modelo falso que não utiliza rede nem consome tokens.
    """

    def __init__(
        self,
        response: LLMAnalysis | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls = 0
        self.last_input: Any = None

    async def ainvoke(
        self,
        model_input: Any,
    ) -> LLMAnalysis:
        self.calls += 1
        self.last_input = model_input

        if self.error is not None:
            raise self.error

        if self.response is None:
            raise RuntimeError(
                "Fake model has no response."
            )

        return self.response.model_copy(
            deep=True
        )


def build_vt_result() -> ProviderResult:
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
                            "malicious": 25,
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


def build_workflow(
    tmp_path: Path,
    analysis_model: FakeStructuredModel,
) -> TriageWorkflow:
    settings = Settings(
        app_env="test",
        enable_genai=True,

        # Não existe chave real neste teste.
        openai_api_key=None,

        database_path=tmp_path / "cti.db",
        csv_export_path=(
            tmp_path / "history.csv"
        ),
    )

    repository = TriageRepository(
        database_path=settings.database_path,
        csv_path=settings.csv_export_path,
    )

    return TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            build_mb_result()
        ),
        repository=repository,
        analysis_model=analysis_model,
    )


def test_genai_branch_uses_mock_without_tokens(
    tmp_path: Path,
) -> None:
    generated_analysis = LLMAnalysis(
        verdict="malicious",
        confidence="high",
        executive_summary=(
            "MOCK_GENAI_EXECUTED: análise "
            "estruturada produzida pelo modelo falso."
        ),
        hunting_hypotheses=[
            (
                "Hipótese sintética produzida "
                "pelo modelo falso."
            )
        ],
        analytic_caveats=[
            (
                "Resultado gerado exclusivamente "
                "para teste."
            )
        ],
    )

    fake_model = FakeStructuredModel(
        response=generated_analysis
    )

    workflow = build_workflow(
        tmp_path,
        fake_model,
    )

    request = TriageRequest(
        hash="a" * 64,
        use_genai=True,
    )

    result = asyncio.run(
        workflow.run(request)
    )

    assert fake_model.calls == 1
    assert fake_model.last_input is not None

    assert result.analysis is not None

    assert (
        "MOCK_GENAI_EXECUTED"
        in result.analysis.executive_summary
    )

    assert result.source_errors == []

    # O prompt contém somente os dados normalizados,
    # e não o objeto bruto "report".
    serialized_input = str(
        fake_model.last_input
    )

    assert "<evidence_json>" in serialized_input
    assert '"report"' not in serialized_input

    # Confirma que o resultado passou pelo nó persist.
    stored = workflow.repository.get(
        result.scan_id
    )

    assert stored is not None
    assert stored.analysis is not None

    assert (
        "MOCK_GENAI_EXECUTED"
        in stored.analysis.executive_summary
    )


def test_request_can_disable_genai(
    tmp_path: Path,
) -> None:
    generated_analysis = LLMAnalysis(
        verdict="malicious",
        confidence="high",
        executive_summary=(
            "MOCK_SHOULD_NOT_EXECUTE"
        ),
    )

    fake_model = FakeStructuredModel(
        response=generated_analysis
    )

    workflow = build_workflow(
        tmp_path,
        fake_model,
    )

    request = TriageRequest(
        hash="a" * 64,
        use_genai=False,
    )

    result = asyncio.run(
        workflow.run(request)
    )

    assert fake_model.calls == 0
    assert result.analysis is not None

    assert (
        "MOCK_SHOULD_NOT_EXECUTE"
        not in result.analysis.executive_summary
    )


def test_genai_failure_preserves_baseline(
    tmp_path: Path,
) -> None:
    fake_model = FakeStructuredModel(
        error=RuntimeError(
            "Synthetic model failure"
        )
    )

    workflow = build_workflow(
        tmp_path,
        fake_model,
    )

    request = TriageRequest(
        hash="a" * 64,
        use_genai=True,
    )

    result = asyncio.run(
        workflow.run(request)
    )

    assert fake_model.calls == 1
    assert result.analysis is not None

    # A baseline classificou a amostra pelas
    # detecções do VirusTotal.
    assert result.analysis.verdict == "malicious"
    assert result.analysis.confidence == "high"

    assert any(
        "GenAI indisponível" in error
        for error in result.source_errors
    )

    stored = workflow.repository.get(
        result.scan_id
    )

    assert stored is not None
    assert stored.analysis is not None
    assert stored.analysis.verdict == "malicious"