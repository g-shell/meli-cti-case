from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Protocol

from app.models import ProviderResult, TriageRequest


class HashProvider(Protocol):
    """
    Contrato que todo provedor de consulta de hashes deve implementar.
    """

    async def lookup_hash(
        self,
        artifact_hash: str,
    ) -> ProviderResult:
        ...


class IntelligenceCollector:
    """
    Executa os provedores selecionados em paralelo.
    """

    def __init__(
        self,
        providers: Mapping[str, HashProvider],
    ):
        self.providers = dict(providers)

    async def _collect_one(
        self,
        provider_name: str,
        artifact_hash: str,
    ) -> ProviderResult:
        """
        Executa um único provedor e isola falhas inesperadas.
        """

        client = self.providers.get(
            provider_name
        )

        if client is None:
            return ProviderResult(
                provider=provider_name,
                status="not_configured",
                error=(
                    f"{provider_name} client "
                    "is not registered"
                ),
            )

        try:
            return await client.lookup_hash(
                artifact_hash
            )

        except Exception as exception:
            return ProviderResult(
                provider=provider_name,
                status="error",
                error=(
                    f"{provider_name} unexpected error: "
                    f"{type(exception).__name__}"
                ),
            )

    async def collect(
        self,
        request: TriageRequest,
    ) -> list[ProviderResult]:
        """
        Executa somente os provedores solicitados no TriageRequest.
        """

        tasks = [
            asyncio.create_task(
                self._collect_one(
                    provider_name,
                    request.hash,
                )
            )
            for provider_name in request.providers
        ]

        results = await asyncio.gather(
            *tasks
        )

        return list(results)