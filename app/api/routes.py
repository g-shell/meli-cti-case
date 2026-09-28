from __future__ import annotations

import asyncio
import logging

from typing import Annotated, cast
from uuid import UUID

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import HTMLResponse

from app.models import (
    CTIReport,
    IndicatorEnrichment,
    IndicatorType,
    ObservableOccurrence,
    ObservableType,
    RepositoryStats,
    TriageRequest,
    TriageResult,
)
from app.services.agent import TriageWorkflow
from app.services.enrichment import (
    EnrichmentError,
    IndicatorEnricher,
    InvalidIndicatorError,
)
from app.services.report import (
    build_cti_report,
    render_cti_report_html,
)
from app.services.report_pdf import render_cti_report_pdf
from app.services.storage import TriageRepository


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


def _repository(request: Request) -> TriageRepository:
    return cast(
        TriageRepository,
        request.app.state.repository,
    )


async def _load_scan(
    scan_id: UUID,
    request: Request,
) -> TriageResult:
    result = await asyncio.to_thread(
        _repository(request).get,
        str(scan_id),
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan não encontrado.",
        )

    return result


@router.get(
    "/health",
    tags=["health"],
)
async def health(request: Request) -> dict[str, str]:
    """Verifica se a aplicação está respondendo."""

    settings = request.app.state.settings

    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.app_env,
    }


@router.post(
    "/triage",
    response_model=TriageResult,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    tags=["triage"],
)
async def create_triage(
    payload: TriageRequest,
    request: Request,
) -> TriageResult:
    """
    Executa coleta, normalização, análise, grounding e persistência.
    """

    workflow = cast(
        TriageWorkflow,
        request.app.state.workflow,
    )

    try:
        return await workflow.run(payload)
    except Exception as exc:
        logger.exception("Triage workflow failed.")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível concluir a triagem.",
        ) from exc


@router.get(
    "/scans",
    response_model=list[TriageResult],
    response_model_exclude_none=True,
    tags=["history"],
)
async def list_scans(
    request: Request,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=200,
            description="Quantidade máxima de resultados.",
        ),
    ] = 50,
    artifact_hash: Annotated[
        str | None,
        Query(
            alias="hash",
            min_length=32,
            max_length=64,
            description="Filtra o histórico pelo hash.",
        ),
    ] = None,
) -> list[TriageResult]:
    """Lista o histórico de triagens."""

    return await asyncio.to_thread(
        _repository(request).list,
        limit,
        artifact_hash,
    )


@router.get(
    "/stats",
    response_model=RepositoryStats,
    tags=["history"],
)
async def get_stats(request: Request) -> RepositoryStats:
    """Retorna indicadores resumidos do histórico local."""

    return await asyncio.to_thread(
        _repository(request).get_stats
    )


@router.get(
    "/observables/search",
    response_model=list[ObservableOccurrence],
    tags=["observables"],
)
async def search_observables(
    request: Request,
    value: Annotated[
        str,
        Query(
            min_length=1,
            max_length=2048,
            description=(
                "Valor completo ou fragmento de IP, domínio, URL, "
                "hash, arquivo, mutex ou registro."
            ),
        ),
    ],
    observable_type: Annotated[
        ObservableType | None,
        Query(
            alias="type",
            description="Filtro opcional pelo tipo do observável.",
        ),
    ] = None,
    exact: Annotated[
        bool,
        Query(description="Exige correspondência exata."),
    ] = False,
    limit: Annotated[
        int,
        Query(ge=1, le=500),
    ] = 100,
) -> list[ObservableOccurrence]:
    """Pesquisa observáveis em todos os scans persistidos."""

    return await asyncio.to_thread(
        _repository(request).search_observables,
        value,
        observable_type,
        exact,
        limit,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=TriageResult,
    response_model_exclude_none=True,
    tags=["history"],
)
async def get_scan(
    scan_id: UUID,
    request: Request,
) -> TriageResult:
    """Recupera uma triagem pelo scan_id."""

    return await _load_scan(scan_id, request)


@router.get(
    "/scans/{scan_id}/report",
    response_model=CTIReport,
    response_model_exclude_none=True,
    tags=["reports"],
)
async def get_scan_report(
    scan_id: UUID,
    request: Request,
) -> CTIReport:
    """Retorna o relatório CTI estruturado em JSON."""

    result = await _load_scan(scan_id, request)
    return build_cti_report(result)


@router.get(
    "/scans/{scan_id}/report/html",
    response_class=HTMLResponse,
    tags=["reports"],
)
async def get_scan_report_html(
    scan_id: UUID,
    request: Request,
) -> HTMLResponse:
    """Retorna uma versão HTML imprimível do relatório CTI."""

    result = await _load_scan(scan_id, request)
    report = build_cti_report(result)
    content = render_cti_report_html(report)

    return HTMLResponse(
        content=content,
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'self'; "
                "img-src 'self' data:; base-uri 'none'; "
                "frame-ancestors 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.get(
    "/scans/{scan_id}/report/pdf",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Relatório CTI em PDF.",
        }
    },
    tags=["reports"],
)
async def get_scan_report_pdf(
    scan_id: UUID,
    request: Request,
    inline: Annotated[
        bool,
        Query(description="Exibe no navegador em vez de baixar."),
    ] = False,
) -> Response:
    """
    Relatório CTI em PDF: capa executiva (TLP, BLUF, julgamentos-chave,
    ações P0) e corpo técnico (PIRs, ATT&CK, infraestrutura, IOCs
    defanged, hunting, D3FEND, limitações e anexos).
    """

    result = await _load_scan(scan_id, request)
    report = build_cti_report(result)
    content = await asyncio.to_thread(
        render_cti_report_pdf,
        report,
    )

    disposition = "inline" if inline else "attachment"

    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'{disposition}; filename="CTI-{scan_id}.pdf"'
            ),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/scans/{scan_id}/export.csv",
    response_class=Response,
    tags=["history"],
)
async def export_scan_csv(
    scan_id: UUID,
    request: Request,
) -> Response:
    """Exporta observáveis, famílias e TTPs em CSV."""

    content = await asyncio.to_thread(
        _repository(request).export_scan_csv,
        str(scan_id),
    )

    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan não encontrado.",
        )

    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; "
                f'filename="triage-{scan_id}.csv"'
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


ENRICHMENT_ERROR_STATUS = {
    "not_configured": status.HTTP_503_SERVICE_UNAVAILABLE,
    "not_found": status.HTTP_404_NOT_FOUND,
    "rate_limited": status.HTTP_429_TOO_MANY_REQUESTS,
    "forbidden": status.HTTP_502_BAD_GATEWAY,
    "error": status.HTTP_502_BAD_GATEWAY,
}


async def _enrich(
    indicator_type: IndicatorType,
    value: str,
    force_refresh: bool,
    request: Request,
) -> IndicatorEnrichment:
    enricher = cast(
        IndicatorEnricher,
        request.app.state.enricher,
    )

    try:
        return await enricher.enrich(
            indicator_type,
            value,
            force_refresh,
        )
    except InvalidIndicatorError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except EnrichmentError as exc:
        detail = (
            "Indicador não encontrado no VirusTotal."
            if exc.status == "not_found"
            else f"Falha no provedor: {exc.status}."
        )

        raise HTTPException(
            status_code=ENRICHMENT_ERROR_STATUS.get(
                exc.status,
                status.HTTP_502_BAD_GATEWAY,
            ),
            detail=detail,
        ) from exc


@router.get(
    "/enrich/ip/{ip}",
    response_model=IndicatorEnrichment,
    response_model_exclude_none=True,
    tags=["enrichment"],
)
async def enrich_ip(
    ip: Annotated[
        str,
        Path(
            min_length=2,
            max_length=64,
            description="IPv4/IPv6 público. Aceita notação defanged (1.2.3[.]4).",
        ),
    ],
    request: Request,
    force_refresh: Annotated[
        bool,
        Query(description="Ignora o cache local."),
    ] = False,
) -> IndicatorEnrichment:
    """
    Reputação ao vivo no VirusTotal (ASN, país, detecções,
    resoluções passivas) e avistamentos no histórico local.
    """

    return await _enrich("ip", ip, force_refresh, request)


@router.get(
    "/enrich/domain/{domain}",
    response_model=IndicatorEnrichment,
    response_model_exclude_none=True,
    tags=["enrichment"],
)
async def enrich_domain(
    domain: Annotated[
        str,
        Path(
            min_length=3,
            max_length=253,
            description="Domínio. Aceita notação defanged (example[.]com).",
        ),
    ],
    request: Request,
    force_refresh: Annotated[
        bool,
        Query(description="Ignora o cache local."),
    ] = False,
) -> IndicatorEnrichment:
    """
    Reputação ao vivo no VirusTotal (registrar, criação, categorias,
    DNS, resoluções passivas) e avistamentos no histórico local.
    """

    return await _enrich("domain", domain, force_refresh, request)


@router.get(
    "/enrichments",
    response_model=list[IndicatorEnrichment],
    response_model_exclude_none=True,
    tags=["enrichment"],
)
async def list_enrichments(
    request: Request,
    limit: Annotated[
        int,
        Query(ge=1, le=200),
    ] = 50,
) -> list[IndicatorEnrichment]:
    """Histórico de indicadores enriquecidos (mais recentes primeiro)."""

    return await asyncio.to_thread(
        _repository(request).list_enrichments,
        limit,
    )
