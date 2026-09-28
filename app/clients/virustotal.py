from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.models import ProviderResult, ProviderStatus


class VirusTotalClient:
    """
    Cliente responsável por consultar informações no VirusTotal.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    RELATIONSHIPS = (
        "contacted_ips",
        "contacted_domains",
        "contacted_urls",
        "dropped_files",
    )

    def __init__(
        self,
        api_key: str | None,
        timeout: float = 30.0,
        max_items: int = 20,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.api_key = api_key.strip() if api_key else None
        self.timeout = timeout
        self.max_items = max_items
        self.transport = transport

    @staticmethod
    def _map_http_status(
        status_code: int,
    ) -> ProviderStatus:
        """
        Converte códigos HTTP para os status internos.
        """

        status_mapping: dict[int, ProviderStatus] = {
            401: "forbidden",
            403: "forbidden",
            404: "not_found",
            429: "rate_limited",
        }

        return status_mapping.get(
            status_code,
            "error",
        )

    async def _get_json(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Executa um GET e retorna uma resposta JSON.
        """

        response = await client.get(
            path,
            params=params,
        )

        response.raise_for_status()

        payload: Any = response.json()

        if not isinstance(payload, dict):
            raise ValueError(
                "VirusTotal returned a non-object JSON response"
            )

        return payload

    async def _collect_enrichment(
        self,
        client: httpx.AsyncClient,
        artifact_hash: str,
    ) -> dict[str, dict[str, Any]]:
        """
        Coleta relacionamentos e informações comportamentais.

        Uma falha nesta etapa não invalida o relatório principal.
        """

        tasks: dict[
            str,
            asyncio.Task[dict[str, Any]],
        ] = {
            relationship: asyncio.create_task(
                self._get_json(
                    client,
                    f"/files/{artifact_hash}/{relationship}",
                    params={
                        "limit": self.max_items,
                    },
                )
            )
            for relationship in self.RELATIONSHIPS
        }

        tasks["behaviour_summary"] = asyncio.create_task(
            self._get_json(
                client,
                f"/files/{artifact_hash}/behaviour_summary",
            )
        )

        enrichment: dict[
            str,
            dict[str, Any],
        ] = {}

        for name, task in tasks.items():
            try:
                payload = await task

                enrichment[name] = {
                    "available": True,
                    "payload": payload,
                }

            except httpx.HTTPStatusError as exception:
                enrichment[name] = {
                    "available": False,
                    "http_status": exception.response.status_code,
                    "error": "http_error",
                }

            except (
                httpx.TimeoutException,
                httpx.RequestError,
            ) as exception:
                enrichment[name] = {
                    "available": False,
                    "error": type(exception).__name__,
                }

            except ValueError:
                enrichment[name] = {
                    "available": False,
                    "error": "invalid_json",
                }

            except Exception as exception:
                enrichment[name] = {
                    "available": False,
                    "error": type(exception).__name__,
                }

        return enrichment

    async def lookup_indicator(
        self,
        indicator_type: str,
        value: str,
    ) -> ProviderResult:
        """
        Consulta reputação e resoluções passivas de um IP ou domínio.

        O valor precisa ter sido validado e normalizado pelo chamador.
        """

        collection = {
            "ip": "ip_addresses",
            "domain": "domains",
        }.get(indicator_type)

        if collection is None:
            raise ValueError(
                f"unsupported indicator type: {indicator_type}"
            )

        if not self.api_key:
            return ProviderResult(
                provider="virustotal",
                status="not_configured",
                error="VIRUSTOTAL_API_KEY is not set",
            )

        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers=headers,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                report, resolutions = await asyncio.gather(
                    self._get_json(
                        client,
                        f"/{collection}/{value}",
                    ),
                    self._get_json(
                        client,
                        f"/{collection}/{value}/resolutions",
                        params={"limit": self.max_items},
                    ),
                    return_exceptions=True,
                )

                if isinstance(report, BaseException):
                    raise report

                # Resoluções são complementares: falha não invalida
                # a reputação principal.
                if isinstance(resolutions, BaseException):
                    resolutions = {}

                return ProviderResult(
                    provider="virustotal",
                    status="ok",
                    data={
                        "report": report,
                        "resolutions": resolutions,
                    },
                )

        except httpx.HTTPStatusError as exception:
            status_code = exception.response.status_code

            return ProviderResult(
                provider="virustotal",
                status=self._map_http_status(status_code),
                error=f"VirusTotal HTTP {status_code}",
            )

        except (
            httpx.TimeoutException,
            httpx.RequestError,
        ) as exception:
            return ProviderResult(
                provider="virustotal",
                status="error",
                error=(
                    "VirusTotal transport error: "
                    f"{type(exception).__name__}"
                ),
            )

        except ValueError:
            return ProviderResult(
                provider="virustotal",
                status="error",
                error="VirusTotal returned invalid JSON",
            )

    async def lookup_hash(
        self,
        artifact_hash: str,
    ) -> ProviderResult:
        """
        Consulta o relatório principal e tenta enriquecê-lo.
        """

        if not self.api_key:
            return ProviderResult(
                provider="virustotal",
                status="not_configured",
                error="VIRUSTOTAL_API_KEY is not set",
            )

        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers=headers,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                report = await self._get_json(
                    client,
                    f"/files/{artifact_hash}",
                )

                related = await self._collect_enrichment(
                    client,
                    artifact_hash,
                )

                return ProviderResult(
                    provider="virustotal",
                    status="ok",
                    data={
                        "report": report,
                        "related": related,
                    },
                )

        except httpx.HTTPStatusError as exception:
            status_code = exception.response.status_code

            return ProviderResult(
                provider="virustotal",
                status=self._map_http_status(status_code),
                error=f"VirusTotal HTTP {status_code}",
            )

        except (
            httpx.TimeoutException,
            httpx.RequestError,
        ) as exception:
            return ProviderResult(
                provider="virustotal",
                status="error",
                error=(
                    "VirusTotal transport error: "
                    f"{type(exception).__name__}"
                ),
            )

        except ValueError:
            return ProviderResult(
                provider="virustotal",
                status="error",
                error="VirusTotal returned invalid JSON",
            )