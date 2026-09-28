from __future__ import annotations

import re
from collections import Counter
from typing import Any

from app.models import (
    Evidence,
    Observable,
    ObservableType,
    ProviderResult,
)
from app.services.context_filters import (
    known_infrastructure_owner,
)


FAMILY_NOISE = {
    "trojan",
    "malware",
    "generic",
    "heur",
    "heuristic",
    "win32",
    "win64",
    "w32",
    "agent",
    "variant",
    "unsafe",
    "suspicious",
    "riskware",
    "packed",
    "application",
    "possible",
    "gen",
    "macos",
    "osx",
    # Categorias funcionais, não nomes de família.
    "stealer",
    "infostealer",
    "dropper",
    "downloader",
    "loader",
    "psw",
    "script",
    "shell",
    "txt",
    "linux",
    "android",
    "x86",
    "x64",
    "arm",
    "arm64",
}


class EvidenceBuilder:
    """
    Cria evidências com identificadores sequenciais.
    """

    def __init__(self) -> None:
        self.items: list[Evidence] = []

    def add(
        self,
        source: str,
        kind: str,
        value: Any,
        observed: bool = True,
    ) -> str:
        evidence_id = (
            f"E{len(self.items) + 1:03d}"
        )

        evidence = Evidence(
            id=evidence_id,
            source=source,
            kind=kind,
            value=value,
            observed=observed,
        )

        self.items.append(
            evidence
        )

        return evidence_id


def _get_enrichment_payload(
    related: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    """
    Extrai o payload de um enriquecimento disponível.
    """

    item = related.get(
        name,
        {},
    )

    if not isinstance(item, dict):
        return {}

    # Estrutura criada pelo VirusTotalClient:
    # {
    #     "available": True,
    #     "payload": {...}
    # }
    if "available" in item:
        if item.get("available") is not True:
            return {}

        payload = item.get(
            "payload",
            {},
        )

        return (
            payload
            if isinstance(payload, dict)
            else {}
        )

    # Compatibilidade com uma estrutura sem wrapper.
    if "data" in item:
        return item

    return {}


def _relationship_observables(
    related: dict[str, Any],
) -> list[Observable]:
    """
    Converte relacionamentos do VirusTotal em observáveis.
    """

    mapping: dict[
        str,
        ObservableType,
    ] = {
        "contacted_ips": "ip",
        "contacted_domains": "domain",
        "contacted_urls": "url",
        "dropped_files": "hash",
    }

    output: list[Observable] = []

    for relationship, observable_type in mapping.items():
        payload = _get_enrichment_payload(
            related,
            relationship,
        )

        rows = payload.get(
            "data",
            [],
        )

        if not isinstance(rows, list):
            continue

        for item in rows:
            if not isinstance(item, dict):
                continue

            attributes = item.get(
                "attributes",
                {},
            )

            if not isinstance(attributes, dict):
                attributes = {}

            if observable_type == "url":
                value = attributes.get(
                    "url"
                )
            else:
                value = item.get(
                    "id"
                )

            if not isinstance(value, str):
                continue

            value = value.strip()

            if not value:
                continue

            context: dict[str, Any] = {}

            analysis_stats = attributes.get(
                "last_analysis_stats"
            )

            if isinstance(analysis_stats, dict):
                context["last_analysis_stats"] = (
                    analysis_stats
                )

            output.append(
                Observable(
                    type=observable_type,
                    value=value,
                    source="virustotal",
                    relationship=relationship,
                    confidence="high",
                    context=context,
                )
            )

    return output


def _dropped_file_family_signals(
    related: dict[str, Any],
    builder: EvidenceBuilder,
    features: dict[str, Any],
) -> None:
    """
    Registra o rótulo de família dos arquivos dropados.

    São sinais de cadeia (scope=related): corroboram, mas não
    identificam sozinhos, a família da amostra principal.
    """

    payload = _get_enrichment_payload(
        related,
        "dropped_files",
    )

    rows = payload.get("data", [])

    if not isinstance(rows, list):
        return

    for item in rows[:20]:
        if not isinstance(item, dict):
            continue

        attributes = item.get("attributes", {})

        if not isinstance(attributes, dict):
            continue

        classification = attributes.get(
            "popular_threat_classification"
        )

        if not isinstance(classification, dict):
            continue

        label = classification.get(
            "suggested_threat_label"
        )

        if not label:
            continue

        evidence_id = builder.add(
            source="virustotal",
            kind="related_family_label",
            value={
                "relation": "dropped_file",
                "sha256": item.get("id"),
                "label": str(label),
                "popular_threat_name": classification.get(
                    "popular_threat_name"
                ),
            },
        )

        features["family_signals"].append(
            {
                "family": str(label),
                "source": "virustotal",
                "evidence_id": evidence_id,
                "scope": "related",
            }
        )


def _behaviour_observables(
    related: dict[str, Any],
) -> list[Observable]:
    """
    Extrai observáveis de rede, mutex e registro do sandbox.
    """

    behaviour = _get_enrichment_payload(
        related,
        "behaviour_summary",
    )

    data = behaviour.get(
        "data",
        {},
    )

    if not isinstance(data, dict):
        return []

    output: list[Observable] = []

    for lookup in data.get(
        "dns_lookups",
        [],
    ) or []:
        if isinstance(lookup, dict):
            hostname = lookup.get(
                "hostname"
            )
        else:
            hostname = str(lookup)

        if hostname:
            output.append(
                Observable(
                    type="domain",
                    value=str(hostname),
                    source="virustotal",
                    relationship="sandbox_dns",
                    confidence="high",
                )
            )

    for traffic in data.get(
        "ip_traffic",
        [],
    ) or []:
        if not isinstance(traffic, dict):
            continue

        destination_ip = traffic.get(
            "destination_ip"
        )

        if not destination_ip:
            continue

        output.append(
            Observable(
                type="ip",
                value=str(destination_ip),
                source="virustotal",
                relationship="sandbox_network",
                confidence="high",
                context={
                    "destination_port": traffic.get(
                        "destination_port"
                    ),
                    "transport_layer_protocol": traffic.get(
                        "transport_layer_protocol"
                    ),
                },
            )
        )

    for mutex in data.get(
        "mutexes_created",
        [],
    ) or []:
        output.append(
            Observable(
                type="mutex",
                value=str(mutex),
                source="virustotal",
                relationship="sandbox_mutex",
                confidence="high",
            )
        )

    for registry_key in data.get(
        "registry_keys_set",
        [],
    ) or []:
        output.append(
            Observable(
                type="registry",
                value=str(registry_key),
                source="virustotal",
                relationship="sandbox_registry",
                confidence="high",
            )
        )

    return output


def _normalize_virustotal(
    provider: ProviderResult,
    builder: EvidenceBuilder,
    observables: list[Observable],
    features: dict[str, Any],
) -> None:
    """
    Normaliza o resultado do VirusTotal.
    """

    report = provider.data.get(
        "report",
        {},
    )

    if not isinstance(report, dict):
        report = {}

    file_object = report.get(
        "data",
        {},
    )

    if not isinstance(file_object, dict):
        file_object = {}

    attributes = file_object.get(
        "attributes",
        {},
    )

    if not isinstance(attributes, dict):
        attributes = {}

    analysis_stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    if not isinstance(analysis_stats, dict):
        analysis_stats = {}

    builder.add(
        source="virustotal",
        kind="detection_stats",
        value=analysis_stats,
    )

    builder.add(
        source="virustotal",
        kind="file_metadata",
        value={
            "sha256": attributes.get(
                "sha256"
            ),
            "sha1": attributes.get(
                "sha1"
            ),
            "md5": attributes.get(
                "md5"
            ),
            "size": attributes.get(
                "size"
            ),
            "type_description": attributes.get(
                "type_description"
            ),
            "first_submission_date": attributes.get(
                "first_submission_date"
            ),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
            "names": (
                attributes.get("names")
                or []
            )[:20],
            "tags": (
                attributes.get("tags")
                or []
            ),
        },
    )

    classification = attributes.get(
        "popular_threat_classification"
    )

    if isinstance(classification, dict):
        if classification:
            evidence_id = builder.add(
                source="virustotal",
                kind="popular_threat_classification",
                value=classification,
            )

            family_label = classification.get(
                "suggested_threat_label"
            )

            if family_label:
                features["family_signals"].append(
                    {
                        "family": str(
                            family_label
                        ),
                        "source": "virustotal",
                        "evidence_id": evidence_id,
                    }
                )

    yara_results = attributes.get(
        "crowdsourced_yara_results",
        [],
    ) or []

    for yara_result in yara_results[:50]:
        if not isinstance(yara_result, dict):
            continue

        builder.add(
            source="virustotal",
            kind="yara_match",
            value={
                key: yara_result.get(key)
                for key in (
                    "rule_name",
                    "ruleset_name",
                    "description",
                    "author",
                )
            },
        )

    related = provider.data.get(
        "related",
        {},
    )

    if not isinstance(related, dict):
        related = {}

    observables.extend(
        _relationship_observables(
            related
        )
    )

    _dropped_file_family_signals(
        related,
        builder,
        features,
    )

    observables.extend(
        _behaviour_observables(
            related
        )
    )

    behaviour = _get_enrichment_payload(
        related,
        "behaviour_summary",
    )

    behaviour_data = behaviour.get(
        "data",
        {},
    )

    if not isinstance(behaviour_data, dict):
        return

    for command in (
        behaviour_data.get(
            "command_executions",
            [],
        )
        or []
    )[:50]:
        command_value = str(command)

        evidence_id = builder.add(
            source="virustotal",
            kind="sandbox_command",
            value=command_value,
        )

        features["commands"].append(
            {
                "value": command_value,
                "evidence_id": evidence_id,
            }
        )

    for path in (
        behaviour_data.get(
            "files_written",
            [],
        )
        or []
    )[:100]:
        path_value = str(path)

        evidence_id = builder.add(
            source="virustotal",
            kind="file_written",
            value=path_value,
        )

        features["files_written"].append(
            {
                "value": path_value,
                "evidence_id": evidence_id,
            }
        )

    for registry_key in (
        behaviour_data.get(
            "registry_keys_set",
            [],
        )
        or []
    )[:100]:
        key_value = str(
            registry_key
        )

        evidence_id = builder.add(
            source="virustotal",
            kind="registry_key_set",
            value=key_value,
        )

        features["registry_keys"].append(
            {
                "value": key_value,
                "evidence_id": evidence_id,
            }
        )

    for api_call in (
        behaviour_data.get(
            "calls_highlighted",
            [],
        )
        or []
    )[:50]:
        builder.add(
            source="virustotal",
            kind="highlighted_api_call",
            value=str(api_call),
        )

    for sigma_result in (
        behaviour_data.get(
            "sigma_analysis_results",
            [],
        )
        or []
    )[:50]:
        builder.add(
            source="virustotal",
            kind="sigma_match",
            value=sigma_result,
        )


def _normalize_malwarebazaar(
    provider: ProviderResult,
    builder: EvidenceBuilder,
    features: dict[str, Any],
) -> None:
    """
    Normaliza o resultado do MalwareBazaar.
    """

    rows = provider.data.get(
        "data",
        [],
    )

    if not isinstance(rows, list):
        return

    if not rows:
        return

    row = rows[0]

    if not isinstance(row, dict):
        return

    builder.add(
        source="malwarebazaar",
        kind="sample_metadata",
        value={
            key: row.get(key)
            for key in (
                "sha256_hash",
                "sha1_hash",
                "md5_hash",
                "file_name",
                "file_size",
                "file_type",
                "first_seen",
                "last_seen",
                "delivery_method",
                "tags",
            )
        },
    )

    signature = row.get(
        "signature"
    )

    if signature:
        evidence_id = builder.add(
            source="malwarebazaar",
            kind="signature",
            value=str(signature),
        )

        features["family_signals"].append(
            {
                "family": str(signature),
                "source": "malwarebazaar",
                "evidence_id": evidence_id,
            }
        )

    related = provider.data.get("related", {})
    parent = (
        related.get("dropped_by")
        if isinstance(related, dict)
        else None
    )

    if (
        isinstance(parent, dict)
        and parent.get("available") is True
        and isinstance(parent.get("sample"), dict)
    ):
        parent_sample = parent["sample"]
        parent_signature = parent_sample.get("signature")

        evidence_id = builder.add(
            source="malwarebazaar",
            kind="related_family_label",
            value={
                "relation": "dropped_by",
                "sha256": parent.get("sha256"),
                "label": parent_signature,
                "file_name": parent_sample.get("file_name"),
                "file_type": parent_sample.get("file_type"),
                "tags": parent_sample.get("tags"),
                "first_seen": parent_sample.get("first_seen"),
            },
        )

        if parent_signature:
            features["family_signals"].append(
                {
                    "family": str(parent_signature),
                    "source": "malwarebazaar",
                    "evidence_id": evidence_id,
                    "scope": "related",
                }
            )

    vendor_intel = row.get(
        "vendor_intel",
        {},
    )

    if not isinstance(vendor_intel, dict):
        return

    for vendor, detection in vendor_intel.items():
        if not isinstance(detection, dict):
            continue

        builder.add(
            source="malwarebazaar",
            kind="vendor_intel",
            value={
                "vendor": vendor,
                **detection,
            },
        )


def normalize_providers(
    providers: list[ProviderResult],
) -> tuple[
    list[Observable],
    list[Evidence],
    dict[str, Any],
]:
    """
    Transforma resultados externos em contratos internos.
    """

    builder = EvidenceBuilder()

    observables: list[Observable] = []

    features: dict[str, Any] = {
        "family_signals": [],
        "commands": [],
        "files_written": [],
        "registry_keys": [],
    }

    for provider in providers:
        if provider.status != "ok":
            builder.add(
                source=provider.provider,
                kind="source_status",
                value={
                    "status": provider.status,
                    "error": provider.error,
                },
            )

            continue

        if provider.provider == "virustotal":
            _normalize_virustotal(
                provider,
                builder,
                observables,
                features,
            )

        elif provider.provider == "malwarebazaar":
            _normalize_malwarebazaar(
                provider,
                builder,
                features,
            )

    deduplicated: list[Observable] = []

    seen: set[
        tuple[str, str]
    ] = set()

    for observable in observables:
        deduplication_key = (
            observable.type,
            observable.value.casefold(),
        )

        if deduplication_key in seen:
            continue

        seen.add(
            deduplication_key
        )

        evidence_id = builder.add(
            source=observable.source,
            kind=(
                "observable_"
                f"{observable.relationship or 'related'}"
            ),
            value={
                "type": observable.type,
                "value": observable.value,
            },
        )

        context = dict(
            observable.context
        )

        context["evidence_id"] = (
            evidence_id
        )

        owner = known_infrastructure_owner(
            observable.type,
            observable.value,
        )

        if owner:
            context["known_infrastructure"] = owner

        deduplicated.append(
            observable.model_copy(
                update={
                    "context": context,
                }
            )
        )

    return (
        deduplicated,
        builder.items,
        features,
    )


def tokenize_family(
    value: str,
) -> list[str]:
    """
    Remove termos genéricos de uma possível família.
    """

    tokens = re.findall(
        r"[a-z0-9]{3,}",
        value.lower(),
    )

    return [
        token
        for token in tokens
        if token not in FAMILY_NOISE
        and not token.isdigit()
    ]


def family_consensus(
    features: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Agrupa sinais de famílias por fontes independentes.

    Sinais "primary" rotulam a própria amostra; sinais "related"
    rotulam artefatos da cadeia (pai que a dropou, arquivos que
    ela dropou). Critério de confiança:

    - high: rótulo da amostra em 2+ provedores independentes;
    - medium: rótulo da amostra corroborado pela cadeia, ou
      rótulo de cadeia presente em 2+ provedores;
    - low: fonte única ou apenas um sinal de cadeia.
    """

    signals = features.get(
        "family_signals",
        [],
    )

    counter: Counter[str] = Counter()

    evidence_by_token: dict[
        str,
        list[str],
    ] = {}

    primary_sources: dict[str, set[str]] = {}
    related_sources: dict[str, set[str]] = {}

    for signal in signals:
        if not isinstance(signal, dict):
            continue

        family = signal.get(
            "family"
        )

        source = signal.get(
            "source"
        )

        evidence_id = signal.get(
            "evidence_id"
        )

        if not (
            isinstance(family, str)
            and isinstance(source, str)
            and isinstance(evidence_id, str)
        ):
            continue

        scope_sources = (
            related_sources
            if signal.get("scope") == "related"
            else primary_sources
        )

        unique_tokens = dict.fromkeys(
            tokenize_family(family)
        )

        for token in unique_tokens:
            counter[token] += 1

            evidence_by_token.setdefault(
                token,
                [],
            ).append(
                evidence_id
            )

            scope_sources.setdefault(
                token,
                set(),
            ).add(
                source
            )

    output: list[
        dict[str, Any]
    ] = []

    for token, signal_count in counter.most_common(5):
        primary = primary_sources.get(token, set())
        related = related_sources.get(token, set())

        independent_sources = len(primary)

        if independent_sources >= 2:
            confidence = "high"
        elif (
            (primary and related)
            or len(related) >= 2
        ):
            confidence = "medium"
        else:
            confidence = "low"

        output.append(
            {
                "family": token,
                "confidence": confidence,
                "evidence_ids": list(
                    dict.fromkeys(
                        evidence_by_token[
                            token
                        ]
                    )
                ),
                "independent_sources": independent_sources,
                "primary_sources": sorted(primary),
                "related_sources": sorted(related),
                "signal_count": signal_count,
            }
        )

    rank = {"high": 0, "medium": 1, "low": 2}

    # Estável: mantém a ordem por contagem dentro do mesmo nível.
    output.sort(key=lambda item: rank[item["confidence"]])

    return output
