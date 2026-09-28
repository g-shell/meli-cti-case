import asyncio

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from fastapi.testclient import TestClient

from app.clients.virustotal import VirusTotalClient
from app.config import Settings
from app.main import create_app
from app.models import ProviderResult
from app.services.enrichment import (
    IndicatorEnricher,
    InvalidIndicatorError,
    build_enrichment,
    normalize_domain,
    normalize_ip,
)
from app.services.storage import TriageRepository


def ip_report() -> dict:
    return {
        "report": {
            "data": {
                "id": "89.169.54.153",
                "attributes": {
                    "as_owner": "Aeza Group LLC",
                    "asn": 210644,
                    "country": "DE",
                    "network": "89.169.54.0/24",
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 1,
                        "harmless": 50,
                    },
                },
            }
        },
        "resolutions": {
            "data": [
                {
                    "attributes": {
                        "host_name": "book.wi-7-e.ru",
                        "date": 1761523200,
                    }
                },
                {"attributes": {"ip_address": "ignored"}},
            ]
        },
    }


class FakeIndicatorClient:
    def __init__(
        self,
        result: ProviderResult,
    ) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    async def lookup_indicator(
        self,
        indicator_type: str,
        value: str,
    ) -> ProviderResult:
        self.calls.append((indicator_type, value))
        return self.result


def build_enricher(
    tmp_path: Path,
    result: ProviderResult,
) -> tuple[IndicatorEnricher, FakeIndicatorClient]:
    settings = Settings(
        database_path=tmp_path / "cti.db",
        csv_export_path=tmp_path / "history.csv",
    )
    repository = TriageRepository(
        database_path=settings.database_path,
        csv_path=settings.csv_export_path,
    )
    fake = FakeIndicatorClient(result)

    return (
        IndicatorEnricher(
            settings=settings,
            repository=repository,
            vt_client=fake,
        ),
        fake,
    )


def test_normalizes_and_refangs_indicators() -> None:
    assert normalize_ip("89.169.54[.]153") == "89.169.54.153"
    assert normalize_ip(" 2606:4700:4700::1111 ") == "2606:4700:4700::1111"
    assert normalize_domain("Book.WI-7-E[.]RU.") == "book.wi-7-e.ru"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "value",
    ["10.0.0.5", "127.0.0.1", "192.168.1.10", "169.254.1.1", "::1", "abc"],
)
def test_rejects_non_public_or_invalid_ips(value: str) -> None:
    with pytest.raises(InvalidIndicatorError):
        normalize_ip(value)


@pytest.mark.parametrize(
    "value",
    ["localhost", "-bad.com", "a..com", "1.2.3.4", "x" * 64 + ".com", "example.123"],
)
def test_rejects_invalid_domains(value: str) -> None:
    with pytest.raises(InvalidIndicatorError):
        normalize_domain(value)


def test_build_enrichment_maps_ip_report() -> None:
    enrichment = build_enrichment(
        "ip",
        "89.169.54.153",
        ProviderResult(
            provider="virustotal",
            status="ok",
            data=ip_report(),
        ),
    )

    assert enrichment.verdict == "malicious"
    assert enrichment.as_owner == "Aeza Group LLC"
    assert enrichment.asn == 210644
    assert enrichment.known_infrastructure is None
    assert [item.value for item in enrichment.resolutions] == [
        "book.wi-7-e.ru"
    ]


def test_known_infrastructure_is_flagged() -> None:
    enrichment = build_enrichment(
        "ip",
        "17.253.7.201",
        ProviderResult(
            provider="virustotal",
            status="ok",
            data={
                "report": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 0},
                        }
                    }
                }
            },
        ),
    )

    assert enrichment.verdict == "no_detections"
    assert enrichment.known_infrastructure == "Apple"


def test_enricher_uses_cache_until_ttl(tmp_path: Path) -> None:
    enricher, fake = build_enricher(
        tmp_path,
        ProviderResult(provider="virustotal", status="ok", data=ip_report()),
    )

    first = asyncio.run(enricher.enrich("ip", "89.169.54.153"))
    second = asyncio.run(enricher.enrich("ip", "89.169.54[.]153"))

    assert first.cached is False
    assert second.cached is True
    assert len(fake.calls) == 1

    asyncio.run(
        enricher.enrich("ip", "89.169.54.153", force_refresh=True)
    )
    assert len(fake.calls) == 2

    # Entrada expirada força nova consulta.
    stale = first.model_copy(
        update={
            "fetched_at": datetime.now(timezone.utc) - timedelta(days=2),
        }
    )
    enricher.repository.save_enrichment(stale)

    asyncio.run(enricher.enrich("ip", "89.169.54.153"))
    assert len(fake.calls) == 3


@pytest.fixture
def api(tmp_path: Path) -> Iterator[tuple[TestClient, FakeIndicatorClient]]:
    enricher, fake = build_enricher(
        tmp_path,
        ProviderResult(provider="virustotal", status="ok", data=ip_report()),
    )
    application = create_app(
        settings=Settings(
            enable_genai=False,
            database_path=tmp_path / "cti.db",
            csv_export_path=tmp_path / "history.csv",
        ),
        repository=enricher.repository,
        enricher=enricher,
    )

    with TestClient(application) as client:
        yield client, fake


def test_enrich_ip_endpoint(api) -> None:
    client, _ = api

    response = client.get("/api/v1/enrich/ip/89.169.54[.]153")

    assert response.status_code == 200
    body = response.json()
    assert body["value"] == "89.169.54.153"
    assert body["verdict"] == "malicious"
    assert body["local_sightings"] == []

    history = client.get("/api/v1/enrichments").json()
    assert [item["value"] for item in history] == ["89.169.54.153"]


def test_private_ip_is_not_sent_to_provider(api) -> None:
    client, fake = api

    response = client.get("/api/v1/enrich/ip/10.1.2.3")

    assert response.status_code == 422
    assert fake.calls == []


def test_provider_errors_are_mapped(api) -> None:
    client, fake = api

    fake.result = ProviderResult(
        provider="virustotal",
        status="not_found",
        error="VirusTotal HTTP 404",
    )
    assert client.get("/api/v1/enrich/domain/unknown.example").status_code == 404

    fake.result = ProviderResult(
        provider="virustotal",
        status="rate_limited",
        error="VirusTotal HTTP 429",
    )
    assert client.get("/api/v1/enrich/domain/other.example").status_code == 429


@pytest.mark.asyncio
async def test_vt_client_keeps_report_when_resolutions_fail() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)

        if request.url.path.endswith("/resolutions"):
            return httpx.Response(status_code=403, json={})

        return httpx.Response(
            status_code=200,
            json=ip_report()["report"],
        )

    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=httpx.MockTransport(handler),
    )

    result = await client.lookup_indicator("domain", "wi-7-e.ru")

    assert result.status == "ok"
    assert result.data["resolutions"] == {}
    assert sorted(requested) == [
        "/api/v3/domains/wi-7-e.ru",
        "/api/v3/domains/wi-7-e.ru/resolutions",
    ]
