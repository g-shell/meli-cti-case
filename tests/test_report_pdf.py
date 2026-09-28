import io

from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Evidence
from app.services.report import build_cti_report
from app.services.report_pdf import defang, render_cti_report_pdf
from app.services.storage import TriageRepository

from tests.test_report import build_result


pypdf = pytest.importorskip("pypdf")


def _pages_text(content: bytes) -> list[str]:
    reader = pypdf.PdfReader(io.BytesIO(content))
    return [page.extract_text() for page in reader.pages]


def test_defang_network_indicators() -> None:
    assert defang("domain", "c2.example.test") == "c2[.]example[.]test"
    assert defang("ip", "89.169.54.153") == "89[.]169[.]54[.]153"
    assert defang("url", "https://a.example/x") == "hxxps[://]a[.]example/x"
    assert defang("hash", "a" * 64) == "a" * 64


def test_pdf_structure_and_tlp_on_every_page() -> None:
    report = build_cti_report(build_result())

    content = render_cti_report_pdf(report)

    assert content.startswith(b"%PDF")
    pages = _pages_text(content)
    assert len(pages) >= 3
    assert all("TLP:CLEAR" in page for page in pages)
    assert all(f"de {len(pages)}" in page for page in pages)

    text = "\n".join(pages)
    for heading in (
        "BOTTOM LINE UP FRONT",
        "Julgamentos-chave",
        "Requisitos de inteligência",
        "MITRE ATT&CK",
        "Infraestrutura e avaliação de C2",
        "Indicadores de comprometimento",
        "MITRE D3FEND",
        "Regras de detecção",
        "Anexo — evidências",
    ):
        assert heading in text, heading

    # IOCs de rede sempre defanged no documento, inclusive no anexo...
    assert "c2[.]example[.]test" in text
    without_rules = "\n".join(
        _pages_text(
            render_cti_report_pdf(
                report.model_copy(update={"detection_rules": []})
            )
        )
    )
    assert "c2.example.test" not in without_rules

    # ...exceto dentro das regras, que precisam funcionar ao serem copiadas.
    assert 'dns.question.name : "c2.example.test"' in text

    metadata = pypdf.PdfReader(io.BytesIO(content)).metadata
    assert metadata.title == report.title


def test_untrusted_content_is_escaped_not_interpreted() -> None:
    result = build_result()
    hostile = (
        "<font color='red'>x</font><a href='javascript:alert(1)'>y</a> "
        "& ünïcödé 中文 \x07"
    )
    result.evidence.append(
        Evidence(
            id="E999",
            source="virustotal",
            kind="sandbox_command",
            value=hostile,
        )
    )
    result.analysis.executive_summary = hostile

    content = render_cti_report_pdf(build_cti_report(result))
    text = "\n".join(_pages_text(content))

    assert "<font color='red'>x</font>" in text
    assert "javascript:alert(1)" in text
    assert "ünïcödé" in text
    assert b"/URI" not in content  # nenhum link foi criado


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        enable_genai=False,
        database_path=tmp_path / "cti.db",
        csv_export_path=tmp_path / "history.csv",
    )
    repository = TriageRepository(
        database_path=settings.database_path,
        csv_path=settings.csv_export_path,
    )
    repository.save(build_result())

    with TestClient(
        create_app(settings=settings, repository=repository)
    ) as test_client:
        yield test_client


def test_pdf_endpoint(client: TestClient) -> None:
    scan_id = build_result().scan_id

    response = client.get(f"/api/v1/scans/{scan_id}/report/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.content.startswith(b"%PDF")

    inline = client.get(f"/api/v1/scans/{scan_id}/report/pdf?inline=true")
    assert inline.headers["content-disposition"].startswith("inline;")

    missing = client.get(
        "/api/v1/scans/22222222-2222-4222-8222-222222222222/report/pdf"
    )
    assert missing.status_code == 404


def test_html_report_links_to_pdf(client: TestClient) -> None:
    scan_id = build_result().scan_id

    html = client.get(f"/api/v1/scans/{scan_id}/report/html").text

    assert f"/api/v1/scans/{scan_id}/report/pdf" in html
    assert "Regras de detecção" in html
    # Conteúdo das regras passa pelo autoescape do Jinja2.
    assert 'import &#34;hash&#34;' in html
