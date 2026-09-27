from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import Settings, get_settings
from app.services.agent import TriageWorkflow
from app.services.storage import TriageRepository


APP_DIRECTORY = Path(__file__).resolve().parent
STATIC_DIRECTORY = APP_DIRECTORY / "static"
TEMPLATE_DIRECTORY = APP_DIRECTORY / "templates"


def create_app(
    settings: Settings | None = None,
    workflow: TriageWorkflow | None = None,
    repository: TriageRepository | None = None,
) -> FastAPI:
    """Application factory utilizada em produção e nos testes."""

    resolved_settings = (
        settings
        if settings is not None
        else get_settings()
    )

    if repository is not None:
        resolved_repository = repository
    elif workflow is not None:
        resolved_repository = workflow.repository
    else:
        resolved_repository = TriageRepository(
            database_path=resolved_settings.database_path,
            csv_path=resolved_settings.csv_export_path,
        )

    resolved_workflow = (
        workflow
        if workflow is not None
        else TriageWorkflow(
            settings=resolved_settings,
            repository=resolved_repository,
        )
    )

    application = FastAPI(
        title=resolved_settings.app_name,
        version="1.0.0",
        description=(
            "API para triagem de artefatos, enriquecimento CTI, "
            "atribuição assistida de família e relatório operacional."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    application.state.settings = resolved_settings
    application.state.repository = resolved_repository
    application.state.workflow = resolved_workflow

    application.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIRECTORY)),
        name="static",
    )

    application.include_router(router)

    @application.get(
        "/",
        include_in_schema=False,
        response_class=FileResponse,
    )
    async def frontend() -> FileResponse:
        return FileResponse(
            TEMPLATE_DIRECTORY / "index.html",
            media_type="text/html",
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; "
                    "style-src 'self'; connect-src 'self'; "
                    "img-src 'self' data:; object-src 'none'; "
                    "base-uri 'none'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    return application


app = create_app()
