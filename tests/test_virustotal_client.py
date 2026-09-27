import httpx
import pytest

from app.clients.virustotal import VirusTotalClient


CASE_SHA256 = "a" * 64


@pytest.mark.asyncio
async def test_returns_not_configured_without_api_key():
    client = VirusTotalClient(
        api_key=None,
    )

    result = await client.lookup_hash(
        CASE_SHA256
    )

    assert result.provider == "virustotal"
    assert result.status == "not_configured"
    assert result.data == {}
    assert result.error == "VIRUSTOTAL_API_KEY is not set"


@pytest.mark.asyncio
async def test_preserves_report_when_relationship_is_forbidden():
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        assert request.headers["x-apikey"] == "unit-test-key"

        path = request.url.path

        if path.endswith(
            f"/files/{CASE_SHA256}"
        ):
            return httpx.Response(
                status_code=200,
                json={
                    "data": {
                        "type": "file",
                        "id": CASE_SHA256,
                        "attributes": {
                            "sha256": CASE_SHA256,
                            "last_analysis_stats": {
                                "malicious": 10,
                                "undetected": 20,
                            },
                        },
                    }
                },
            )

        if path.endswith(
            "/contacted_ips"
        ):
            return httpx.Response(
                status_code=403,
                json={
                    "error": {
                        "message": "Forbidden",
                    }
                },
            )

        if path.endswith(
            "/behaviour_summary"
        ):
            return httpx.Response(
                status_code=200,
                json={
                    "data": {
                        "command_executions": [],
                        "files_written": [],
                    }
                },
            )

        return httpx.Response(
            status_code=200,
            json={
                "data": [],
            },
        )

    transport = httpx.MockTransport(
        handler
    )

    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=transport,
    )

    result = await client.lookup_hash(
        CASE_SHA256
    )

    assert result.status == "ok"

    report = result.data["report"]
    related = result.data["related"]

    assert report["data"]["id"] == CASE_SHA256

    assert (
        related["contacted_ips"]["available"]
        is False
    )

    assert (
        related["contacted_ips"]["http_status"]
        == 403
    )

    assert (
        related["contacted_domains"]["available"]
        is True
    )

    assert (
        related["behaviour_summary"]["available"]
        is True
    )


@pytest.mark.asyncio
async def test_maps_main_report_404_to_not_found():
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=404,
            json={
                "error": {
                    "message": "Not found",
                }
            },
        )

    transport = httpx.MockTransport(
        handler
    )

    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=transport,
    )

    result = await client.lookup_hash(
        CASE_SHA256
    )

    assert result.provider == "virustotal"
    assert result.status == "not_found"
    assert result.data == {}
    assert result.error == "VirusTotal HTTP 404"