import pytest

from app.models import ProviderResult, TriageRequest
from app.services.collector import IntelligenceCollector


CASE_SHA256 = "a" * 64


class StubProvider:
    """
    Provedor controlado utilizado somente nos testes.
    """

    def __init__(
        self,
        result: ProviderResult | None = None,
        exception: Exception | None = None,
    ):
        self.result = result
        self.exception = exception
        self.calls: list[str] = []

    async def lookup_hash(
        self,
        artifact_hash: str,
    ) -> ProviderResult:
        self.calls.append(
            artifact_hash
        )

        if self.exception is not None:
            raise self.exception

        if self.result is None:
            raise RuntimeError(
                "StubProvider has no result"
            )

        return self.result


@pytest.mark.asyncio
async def test_collects_both_providers():
    vt_client = StubProvider(
        result=ProviderResult(
            provider="virustotal",
            status="ok",
        )
    )

    mb_client = StubProvider(
        result=ProviderResult(
            provider="malwarebazaar",
            status="ok",
        )
    )

    collector = IntelligenceCollector(
        providers={
            "virustotal": vt_client,
            "malwarebazaar": mb_client,
        }
    )

    request = TriageRequest(
        hash=CASE_SHA256
    )

    results = await collector.collect(
        request
    )

    assert [
        result.provider
        for result in results
    ] == [
        "virustotal",
        "malwarebazaar",
    ]

    assert [
        result.status
        for result in results
    ] == [
        "ok",
        "ok",
    ]

    assert vt_client.calls == [
        CASE_SHA256
    ]

    assert mb_client.calls == [
        CASE_SHA256
    ]


@pytest.mark.asyncio
async def test_collects_only_selected_provider():
    vt_client = StubProvider(
        result=ProviderResult(
            provider="virustotal",
            status="ok",
        )
    )

    mb_client = StubProvider(
        result=ProviderResult(
            provider="malwarebazaar",
            status="ok",
        )
    )

    collector = IntelligenceCollector(
        providers={
            "virustotal": vt_client,
            "malwarebazaar": mb_client,
        }
    )

    request = TriageRequest(
        hash=CASE_SHA256,
        providers=[
            "malwarebazaar",
        ],
    )

    results = await collector.collect(
        request
    )

    assert len(results) == 1
    assert results[0].provider == "malwarebazaar"

    assert vt_client.calls == []

    assert mb_client.calls == [
        CASE_SHA256
    ]


@pytest.mark.asyncio
async def test_isolates_unexpected_provider_failure():
    vt_client = StubProvider(
        exception=RuntimeError(
            "Simulated error"
        )
    )

    mb_client = StubProvider(
        result=ProviderResult(
            provider="malwarebazaar",
            status="ok",
        )
    )

    collector = IntelligenceCollector(
        providers={
            "virustotal": vt_client,
            "malwarebazaar": mb_client,
        }
    )

    request = TriageRequest(
        hash=CASE_SHA256
    )

    results = await collector.collect(
        request
    )

    assert results[0].provider == "virustotal"
    assert results[0].status == "error"
    assert "RuntimeError" in (
        results[0].error or ""
    )

    assert results[1].provider == "malwarebazaar"
    assert results[1].status == "ok"


@pytest.mark.asyncio
async def test_returns_not_configured_for_missing_client():
    mb_client = StubProvider(
        result=ProviderResult(
            provider="malwarebazaar",
            status="ok",
        )
    )

    collector = IntelligenceCollector(
        providers={
            "malwarebazaar": mb_client,
        }
    )

    request = TriageRequest(
        hash=CASE_SHA256,
        providers=[
            "virustotal",
        ],
    )

    results = await collector.collect(
        request
    )

    assert len(results) == 1
    assert results[0].provider == "virustotal"
    assert results[0].status == "not_configured"
    assert results[0].error == (
        "virustotal client is not registered"
    )