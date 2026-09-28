from __future__ import annotations

import asyncio
import ipaddress
import re

from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from app.clients.virustotal import VirusTotalClient
from app.config import Settings
from app.models import (
    IndicatorEnrichment,
    IndicatorType,
    PassiveDNSRecord,
    ProviderResult,
)
from app.services.context_filters import (
    known_infrastructure_owner,
)
from app.services.storage import TriageRepository


DOMAIN_LABEL = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)$"
)

# Limiar para reputação de rede: detecções isoladas em IPs e
# domínios de CDN são comuns e não justificam "malicious".
MALICIOUS_THRESHOLD = 3


class IndicatorLookupClient(Protocol):
    async def lookup_indicator(
        self,
        indicator_type: str,
        value: str,
    ) -> ProviderResult:
        ...


class InvalidIndicatorError(ValueError):
    """Indicador malformado ou que não deve sair da organização."""


class EnrichmentError(Exception):
    """Falha do provedor, com o status interno correspondente."""

    def __init__(
        self,
        status: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.status = status


def refang(value: str) -> str:
    """Aceita IOCs defanged: example[.]com, hxxp, 1.2.3[.]4."""

    return (
        value.strip()
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
    )


def normalize_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(refang(value))
    except ValueError as exception:
        raise InvalidIndicatorError(
            "Endereço IP inválido."
        ) from exception

    # IPs internos não são enviados a terceiros: além de inúteis
    # para reputação pública, revelariam o endereçamento interno.
    if not address.is_global:
        raise InvalidIndicatorError(
            "IP não roteável publicamente (privado, loopback, "
            "reservado ou link-local); não é consultado externamente."
        )

    return str(address)


def normalize_domain(value: str) -> str:
    candidate = refang(value).casefold().rstrip(".")

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise InvalidIndicatorError(
            "Valor é um IP; use o endpoint de IP."
        )

    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exception:
        raise InvalidIndicatorError(
            "Domínio inválido."
        ) from exception

    labels = candidate.split(".")

    if (
        len(candidate) > 253
        or len(labels) < 2
        or not all(DOMAIN_LABEL.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise InvalidIndicatorError("Domínio inválido.")

    return candidate


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, (int, float)) or value <= 0:
        return None

    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _verdict(stats: dict[str, int]) -> str:
    if not stats:
        return "unknown"

    if stats.get("malicious", 0) >= MALICIOUS_THRESHOLD:
        return "malicious"

    if stats.get("malicious", 0) or stats.get("suspicious", 0):
        return "suspicious"

    return "no_detections"


def build_enrichment(
    indicator_type: IndicatorType,
    value: str,
    provider: ProviderResult,
) -> IndicatorEnrichment:
    """Converte a resposta do VirusTotal no contrato interno."""

    report = provider.data.get("report", {})
    data = report.get("data", {}) if isinstance(report, dict) else {}
    attributes = data.get("attributes", {}) if isinstance(data, dict) else {}

    if not isinstance(attributes, dict):
        attributes = {}

    raw_stats = attributes.get("last_analysis_stats", {})
    stats = {
        key: parsed
        for key, raw in (
            raw_stats.items() if isinstance(raw_stats, dict) else []
        )
        if (parsed := _int_or_none(raw)) is not None
    }

    resolutions: list[PassiveDNSRecord] = []
    raw_resolutions = provider.data.get("resolutions", {})
    rows = (
        raw_resolutions.get("data", [])
        if isinstance(raw_resolutions, dict)
        else []
    )

    resolved_key = "host_name" if indicator_type == "ip" else "ip_address"

    for row in rows if isinstance(rows, list) else []:
        row_attributes = row.get("attributes", {}) if isinstance(row, dict) else {}

        if not isinstance(row_attributes, dict):
            continue

        resolved = row_attributes.get(resolved_key)

        if isinstance(resolved, str) and resolved:
            resolutions.append(
                PassiveDNSRecord(
                    value=resolved,
                    last_resolved=_timestamp(row_attributes.get("date")),
                )
            )

    categories = attributes.get("categories", {})
    tags = attributes.get("tags", [])
    dns_records = attributes.get("last_dns_records", [])

    return IndicatorEnrichment(
        indicator_type=indicator_type,
        value=value,
        provider_status=provider.status,
        fetched_at=provider.fetched_at,
        verdict=_verdict(stats),
        reputation=stats,
        known_infrastructure=known_infrastructure_owner(
            indicator_type,
            value,
        ),
        as_owner=attributes.get("as_owner"),
        asn=_int_or_none(attributes.get("asn")),
        country=attributes.get("country"),
        network=attributes.get("network"),
        registrar=attributes.get("registrar"),
        creation_date=_timestamp(attributes.get("creation_date")),
        categories=(
            {str(k): str(v) for k, v in categories.items()}
            if isinstance(categories, dict)
            else {}
        ),
        tags=[str(tag) for tag in tags] if isinstance(tags, list) else [],
        dns_records=[
            {
                "type": str(record.get("type", "")),
                "value": str(record.get("value", "")),
            }
            for record in (dns_records if isinstance(dns_records, list) else [])[:20]
            if isinstance(record, dict)
        ],
        resolutions=resolutions,
    )


class IndicatorEnricher:
    """
    Enriquecimento ao vivo de IPs e domínios com cache em SQLite.
    """

    def __init__(
        self,
        settings: Settings,
        repository: TriageRepository,
        vt_client: IndicatorLookupClient | None = None,
    ) -> None:
        self.repository = repository
        self.cache_ttl = timedelta(
            hours=settings.enrichment_cache_ttl_hours
        )
        self.vt_client = vt_client or VirusTotalClient(
            api_key=settings.virustotal_api_key,
            timeout=settings.request_timeout_seconds,
            max_items=settings.max_relationship_items,
        )

    @staticmethod
    def normalize(
        indicator_type: IndicatorType,
        value: str,
    ) -> str:
        if indicator_type == "ip":
            return normalize_ip(value)

        return normalize_domain(value)

    async def enrich(
        self,
        indicator_type: IndicatorType,
        raw_value: str,
        force_refresh: bool = False,
    ) -> IndicatorEnrichment:
        value = self.normalize(indicator_type, raw_value)

        enrichment: IndicatorEnrichment | None = None

        if not force_refresh:
            cached = await asyncio.to_thread(
                self.repository.get_enrichment,
                indicator_type,
                value,
            )

            if (
                cached is not None
                and datetime.now(timezone.utc) - cached.fetched_at
                < self.cache_ttl
            ):
                enrichment = cached.model_copy(
                    update={"cached": True}
                )

        if enrichment is None:
            provider = await self.vt_client.lookup_indicator(
                indicator_type,
                value,
            )

            if provider.status != "ok":
                raise EnrichmentError(
                    provider.status,
                    provider.error or provider.status,
                )

            enrichment = build_enrichment(
                indicator_type,
                value,
                provider,
            )

            await asyncio.to_thread(
                self.repository.save_enrichment,
                enrichment,
            )

        sightings = await asyncio.to_thread(
            self.repository.search_observables,
            value,
            indicator_type,
            True,
            50,
        )

        return enrichment.model_copy(
            update={"local_sightings": sightings}
        )
