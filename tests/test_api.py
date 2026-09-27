from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import ProviderResult
from app.services.agent import TriageWorkflow
from app.services.storage import TriageRepository


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
            "related": {
                "behaviour_summary": {
                    "available": True,
                    "payload": {
                        "data": {
                            "dns_lookups": [
                                {
                                    "hostname": (
                                        "c2.example.test"
                                    )
                                }
                            ],
                            "command_executions": [
                                "powershell.exe -enc AAAA"
                            ],
                        }
                    },
                }
            },
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


@pytest.fixture
def client(
    tmp_path: Path,
) -> Iterator[TestClient]:
    settings = Settings(
        app_name="CTI Test API",
        app_env="test",
        enable_genai=False,
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

    workflow = TriageWorkflow(
        settings=settings,
        vt_client=FakeClient(
            build_vt_result()
        ),
        mb_client=FakeClient(
            build_mb_result()
        ),
        repository=repository,
    )

    application = create_app(
        settings=settings,
        workflow=workflow,
        repository=repository,
    )

    with TestClient(application) as test_client:
        yield test_client


def test_health(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
        "service": "CTI Test API",
        "environment": "test",
    }


def test_triage_history_and_export(
    client: TestClient,
) -> None:
    create_response = client.post(
        "/api/v1/triage",
        json={
            "hash": "a" * 64,
            "providers": [
                "virustotal",
                "malwarebazaar",
            ],
            "use_genai": False,
            "force_refresh": False,
        },
    )

    assert create_response.status_code == 201

    created = create_response.json()

    assert created["status"] == "completed"
    assert created["requested_hash"] == "a" * 64
    assert created["analysis"]["verdict"] == "malicious"

    scan_id = created["scan_id"]

    get_response = client.get(
        f"/api/v1/scans/{scan_id}"
    )

    assert get_response.status_code == 200
    assert (
        get_response.json()["scan_id"]
        == scan_id
    )

    history_response = client.get(
        "/api/v1/scans",
        params={
            "hash": "a" * 64,
            "limit": 10,
        },
    )

    assert history_response.status_code == 200

    history = history_response.json()

    assert len(history) == 1
    assert history[0]["scan_id"] == scan_id

    export_response = client.get(
        (
            f"/api/v1/scans/{scan_id}"
            "/export.csv"
        )
    )

    assert export_response.status_code == 200

    assert (
        export_response.headers["content-type"]
        .startswith("text/csv")
    )

    assert "emotet" in export_response.text

    report_response = client.get(
        f"/api/v1/scans/{scan_id}/report"
    )

    assert report_response.status_code == 200
    report = report_response.json()
    assert report["scan_id"] == scan_id
    assert report["verdict"] == "malicious"
    assert len(report["intelligence_requirements"]) == 5
    assert report["ttps"][0]["technique_id"] == "T1059.001"

    html_response = client.get(
        f"/api/v1/scans/{scan_id}/report/html"
    )

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith(
        "text/html"
    )
    assert "Content-Security-Policy" in html_response.headers
    assert "Relatório de Inteligência de Ameaças" in html_response.text

    stats_response = client.get("/api/v1/stats")

    assert stats_response.status_code == 200
    assert stats_response.json()["total_scans"] == 1
    assert stats_response.json()["unique_hashes"] == 1

    search_response = client.get(
        "/api/v1/observables/search",
        params={
            "value": "c2.example.test",
            "type": "domain",
            "exact": True,
        },
    )

    assert search_response.status_code == 200
    matches = search_response.json()
    assert len(matches) == 1
    assert (
        matches[0]["observable"]["value"]
        == "c2.example.test"
    )


def test_frontend(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "text/html"
    )
    assert "CTI Triage Console" in response.text
    assert "Content-Security-Policy" in response.headers


def test_validation_and_not_found(
    client: TestClient,
) -> None:
    invalid_hash_response = client.post(
        "/api/v1/triage",
        json={
            "hash": "suposto_hash",
            "use_genai": False,
        },
    )

    assert (
        invalid_hash_response.status_code
        == 422
    )

    missing_scan_id = uuid4()

    missing_response = client.get(
        f"/api/v1/scans/{missing_scan_id}"
    )

    assert missing_response.status_code == 404

    missing_export = client.get(
        (
            f"/api/v1/scans/{missing_scan_id}"
            "/export.csv"
        )
    )

    assert missing_export.status_code == 404

    missing_report = client.get(
        f"/api/v1/scans/{missing_scan_id}/report"
    )

    assert missing_report.status_code == 404

    missing_html_report = client.get(
        (
            f"/api/v1/scans/{missing_scan_id}"
            "/report/html"
        )
    )

    assert missing_html_report.status_code == 404
