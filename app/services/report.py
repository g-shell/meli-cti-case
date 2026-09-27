from __future__ import annotations

import json

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypeAlias

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from app.models import (
    ArtifactProfile,
    CTIReport,
    Evidence,
    FamilyCandidate,
    HuntingChecklistItem,
    InfrastructureAssessment,
    Observable,
    PIRAssessment,
    Recommendation,
    ReportProviderSummary,
    TriageResult,
    TTPAssessment,
)


TEMPLATE_DIRECTORY = (
    Path(__file__).resolve().parent.parent / "templates"
)

NETWORK_OBSERVABLE_TYPES = {
    "ip",
    "domain",
    "url",
}

BEHAVIOR_EVIDENCE_KINDS = {
    "sandbox_command",
    "registry_key_set",
    "file_written",
    "highlighted_api_call",
    "sigma_match",
}

PIRStatus: TypeAlias = Literal[
    "answered",
    "partially_answered",
    "unanswered",
]

ReportConfidence: TypeAlias = Literal[
    "low",
    "medium",
    "high",
]

InfrastructureClassification: TypeAlias = Literal[
    "related_infrastructure",
    "observed_network_activity",
    "candidate_c2",
    "confirmed_c2",
]

CONFIDENCE_RANK: dict[ReportConfidence, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def _unique(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip()

        if not cleaned:
            continue

        key = cleaned.casefold()

        if key in seen:
            continue

        seen.add(key)
        output.append(cleaned)

    return output


def _string(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _positive_int(value: Any) -> int | None:
    try:
        converted = int(value)
    except (TypeError, ValueError):
        return None

    return converted if converted >= 0 else None


def _time_text(value: Any) -> str | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            ).isoformat()
        except (OverflowError, OSError, ValueError):
            return str(value)

    return _string(value)


def _artifact_profile(result: TriageResult) -> ArtifactProfile:
    hashes: dict[str, str] = {
        result.hash_type: result.requested_hash,
    }
    filenames: list[str] = []
    file_types: list[str] = []
    file_sizes: list[int] = []
    tags: list[str] = []
    first_seen: str | None = None
    last_seen: str | None = None

    for evidence in result.evidence:
        if evidence.kind not in {
            "file_metadata",
            "sample_metadata",
        }:
            continue

        if not isinstance(evidence.value, dict):
            continue

        value = evidence.value

        hash_mapping = {
            "md5": ("md5", "md5_hash"),
            "sha1": ("sha1", "sha1_hash"),
            "sha256": ("sha256", "sha256_hash"),
        }

        for algorithm, keys in hash_mapping.items():
            for key in keys:
                candidate = _string(value.get(key))

                if candidate:
                    hashes[algorithm] = candidate.lower()
                    break

        raw_names = value.get("names", [])

        if isinstance(raw_names, list):
            filenames.extend(
                str(item)
                for item in raw_names
                if _string(item)
            )

        filename = _string(value.get("file_name"))

        if filename:
            filenames.append(filename)

        for key in ("type_description", "file_type"):
            file_type = _string(value.get(key))

            if file_type:
                file_types.append(file_type)

        for key in ("size", "file_size"):
            file_size = _positive_int(value.get(key))

            if file_size is not None:
                file_sizes.append(file_size)

        raw_tags = value.get("tags", [])

        if isinstance(raw_tags, list):
            tags.extend(
                str(item)
                for item in raw_tags
                if _string(item)
            )

        if first_seen is None:
            first_seen = _time_text(
                value.get("first_seen")
                or value.get("first_submission_date")
            )

        last_seen_candidate = _time_text(
            value.get("last_seen")
            or value.get("last_analysis_date")
        )

        if last_seen_candidate:
            last_seen = last_seen_candidate

    return ArtifactProfile(
        requested_hash=result.requested_hash,
        hash_type=result.hash_type,
        hashes=hashes,
        filenames=_unique(filenames),
        file_types=_unique(file_types),
        file_sizes=list(dict.fromkeys(file_sizes)),
        tags=_unique(tags),
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _grounded_families(
    result: TriageResult,
    valid_evidence_ids: set[str],
) -> list[FamilyCandidate]:
    if result.analysis is None:
        return []

    output: list[FamilyCandidate] = []

    for candidate in result.analysis.family_candidates:
        supporting = [
            evidence_id
            for evidence_id in candidate.supporting_evidence_ids
            if evidence_id in valid_evidence_ids
        ]
        contradicting = [
            evidence_id
            for evidence_id in candidate.contradicting_evidence_ids
            if evidence_id in valid_evidence_ids
        ]

        if not supporting:
            continue

        output.append(
            candidate.model_copy(
                update={
                    "supporting_evidence_ids": supporting,
                    "contradicting_evidence_ids": contradicting,
                }
            )
        )

    return output


def _grounded_ttps(
    result: TriageResult,
    valid_evidence_ids: set[str],
) -> list[TTPAssessment]:
    if result.analysis is None:
        return []

    output: list[TTPAssessment] = []

    for ttp in result.analysis.ttps:
        evidence_ids = [
            evidence_id
            for evidence_id in ttp.evidence_ids
            if evidence_id in valid_evidence_ids
        ]

        if not evidence_ids:
            continue

        output.append(
            ttp.model_copy(
                update={
                    "evidence_ids": evidence_ids,
                }
            )
        )

    return output


def _infrastructure(
    result: TriageResult,
    valid_evidence_ids: set[str],
) -> list[InfrastructureAssessment]:
    observed_by_key = {
        (observable.type, observable.value.casefold()): observable
        for observable in result.observables
        if observable.type in NETWORK_OBSERVABLE_TYPES
    }

    candidate_keys: set[tuple[str, str]] = set()

    if result.analysis:
        candidate_keys = {
            (observable.type, observable.value.casefold())
            for observable in result.analysis.c2_assessment
            if (
                observable.type in NETWORK_OBSERVABLE_TYPES
                and (
                    observable.type,
                    observable.value.casefold(),
                )
                in observed_by_key
            )
        }

    output: list[InfrastructureAssessment] = []

    for key, observable in observed_by_key.items():
        raw_evidence_id = observable.context.get("evidence_id")
        evidence_ids = (
            [raw_evidence_id]
            if (
                isinstance(raw_evidence_id, str)
                and raw_evidence_id in valid_evidence_ids
            )
            else []
        )

        classification: InfrastructureClassification

        if key in candidate_keys:
            classification = "candidate_c2"
            rationale = (
                "O indicador foi observado ou relacionado à amostra "
                "e selecionado pela análise como possível C2. A "
                "classificação permanece como candidata até existir "
                "corroboração temporal, comportamental e contextual."
            )
        elif (
            observable.relationship
            and observable.relationship.startswith("sandbox_")
        ):
            classification = "observed_network_activity"
            rationale = (
                "Atividade de rede registrada em sandbox. Esse fato "
                "não comprova, isoladamente, função de comando e controle."
            )
        else:
            classification = "related_infrastructure"
            rationale = (
                "Infraestrutura relacionada por fonte externa; requer "
                "validação adicional antes de bloqueio ou atribuição."
            )

        output.append(
            InfrastructureAssessment(
                observable=observable,
                classification=classification,
                rationale=rationale,
                evidence_ids=evidence_ids,
            )
        )

    return output


def _pir_assessments(
    result: TriageResult,
    families: list[FamilyCandidate],
    ttps: list[TTPAssessment],
    infrastructure: list[InfrastructureAssessment],
) -> list[PIRAssessment]:
    analysis = result.analysis
    evidence_by_kind: dict[str, list[str]] = {}

    for item in result.evidence:
        evidence_by_kind.setdefault(item.kind, []).append(item.id)

    if analysis is None:
        verdict = "unknown"
        confidence = "low"
        verdict_summary = (
            "Não foi possível produzir uma avaliação analítica."
        )
    else:
        verdict = analysis.verdict
        confidence = analysis.confidence
        verdict_summary = (
            f"O artefato foi classificado como {verdict}, "
            f"com confiança {confidence}."
        )

    verdict_evidence = evidence_by_kind.get(
        "detection_stats",
        [],
    ) + evidence_by_kind.get("source_status", [])

    verdict_status: PIRStatus = (
        "answered"
        if verdict != "unknown"
        else (
            "partially_answered"
            if verdict_evidence
            else "unanswered"
        )
    )

    if families:
        top_family = families[0]
        family_assessment = (
            f"Principal hipótese: {top_family.family}, com "
            f"confiança {top_family.confidence}."
        )
        family_status: PIRStatus = "answered"
        family_confidence: ReportConfidence = (
            top_family.confidence
        )
        family_evidence = top_family.supporting_evidence_ids
    else:
        family_assessment = (
            "As evidências disponíveis não sustentam a atribuição "
            "a uma família específica."
        )
        family_status = "unanswered"
        family_confidence = "low"
        family_evidence = []

    behavior_evidence = [
        item.id
        for item in result.evidence
        if item.kind in BEHAVIOR_EVIDENCE_KINDS
    ]

    if ttps:
        ttp_status: PIRStatus = "answered"
        ttp_confidence: ReportConfidence = max(
            (ttp.confidence for ttp in ttps),
            key=lambda value: CONFIDENCE_RANK[value],
        )
        ttp_assessment = (
            f"Foram sustentadas {len(ttps)} técnica(s) MITRE ATT&CK "
            "por evidências comportamentais."
        )
        ttp_evidence = _unique(
            [
                evidence_id
                for ttp in ttps
                for evidence_id in ttp.evidence_ids
            ]
        )
    elif behavior_evidence:
        ttp_status = "partially_answered"
        ttp_confidence = "low"
        ttp_assessment = (
            "Há evidências comportamentais, mas nenhuma técnica ATT&CK "
            "foi sustentada após o processo de grounding."
        )
        ttp_evidence = behavior_evidence
    else:
        ttp_status = "unanswered"
        ttp_confidence = "low"
        ttp_assessment = (
            "Não foram recebidas evidências comportamentais suficientes."
        )
        ttp_evidence = []

    candidate_c2 = [
        item
        for item in infrastructure
        if item.classification == "candidate_c2"
    ]
    network_activity = [
        item
        for item in infrastructure
        if item.classification
        in {
            "candidate_c2",
            "observed_network_activity",
        }
    ]

    infrastructure_evidence = _unique(
        [
            evidence_id
            for item in infrastructure
            for evidence_id in item.evidence_ids
        ]
    )

    if candidate_c2:
        c2_status: PIRStatus = "partially_answered"
        c2_confidence: ReportConfidence = "medium"
        c2_assessment = (
            f"Foram identificados {len(candidate_c2)} candidato(s) a C2. "
            "Nenhum foi promovido automaticamente a C2 confirmado."
        )
    elif network_activity:
        c2_status = "partially_answered"
        c2_confidence = "low"
        c2_assessment = (
            "Há atividade de rede observada, sem evidência suficiente "
            "para caracterizar comando e controle."
        )
    else:
        c2_status = "unanswered"
        c2_confidence = "low"
        c2_assessment = (
            "Não foram obtidos observáveis de rede suficientes para "
            "avaliar infraestrutura de comando e controle."
        )

    recommendations = (
        analysis.recommendations
        if analysis
        else []
    )

    return [
        PIRAssessment(
            pir_id="PIR-001",
            question=(
                "O artefato deve ser tratado como malicioso ou suspeito?"
            ),
            status=verdict_status,
            confidence=confidence,
            assessment=verdict_summary,
            evidence_ids=_unique(verdict_evidence),
        ),
        PIRAssessment(
            pir_id="PIR-002",
            question=(
                "Qual família de malware é sustentada pelas evidências?"
            ),
            status=family_status,
            confidence=family_confidence,
            assessment=family_assessment,
            evidence_ids=family_evidence,
        ),
        PIRAssessment(
            pir_id="PIR-003",
            question=(
                "Quais comportamentos e TTPs foram observados?"
            ),
            status=ttp_status,
            confidence=ttp_confidence,
            assessment=ttp_assessment,
            evidence_ids=ttp_evidence,
        ),
        PIRAssessment(
            pir_id="PIR-004",
            question=(
                "Existe infraestrutura de rede ou C2 associada?"
            ),
            status=c2_status,
            confidence=c2_confidence,
            assessment=c2_assessment,
            evidence_ids=infrastructure_evidence,
        ),
        PIRAssessment(
            pir_id="PIR-005",
            question=(
                "Quais ações defensivas devem ser priorizadas?"
            ),
            status=(
                "answered"
                if recommendations
                else "unanswered"
            ),
            confidence=(
                "high"
                if recommendations
                else "low"
            ),
            assessment=(
                f"Foram definidas {len(recommendations)} recomendações "
                "priorizadas de contenção, detecção e hardening."
                if recommendations
                else (
                    "Não há recomendações estruturadas disponíveis."
                )
            ),
            evidence_ids=[],
        ),
    ]


def _hunting_checklist(
    artifact: ArtifactProfile,
    observables: list[Observable],
) -> list[HuntingChecklistItem]:
    network_values = [
        observable.value
        for observable in observables
        if observable.type in NETWORK_OBSERVABLE_TYPES
    ][:20]

    items = [
        HuntingChecklistItem(
            priority="P0",
            data_source="EDR / inventário de software",
            objective=(
                "Determinar prevalência, first seen e hosts afetados."
            ),
            procedure=(
                "Pesquisar os hashes do artefato em todos os endpoints; "
                "registrar caminho, usuário, hostname, processo e horário."
            ),
            expected_evidence=[
                "Caminho do arquivo e timestamps",
                "Usuário e host associados",
                "Processo pai e processos filhos",
                "Prevalência por grupo de ativos",
            ],
        ),
        HuntingChecklistItem(
            priority="P0",
            data_source="EDR / telemetria de processos",
            objective=(
                "Reconstruir a cadeia de execução e o vetor inicial."
            ),
            procedure=(
                "Inspecionar árvore de processos, linha de comando, "
                "assinatura, processo pai, arquivos gravados e conexões."
            ),
            expected_evidence=[
                "Process tree completa",
                "Command line e parent command line",
                "Arquivos criados ou modificados",
                "Conexões iniciadas pelo processo",
            ],
        ),
        HuntingChecklistItem(
            priority="P1",
            data_source="DNS / proxy / firewall / NDR",
            objective=(
                "Validar alcance e temporalidade da infraestrutura relacionada."
            ),
            procedure=(
                "Pesquisar os observáveis de rede antes e depois da execução; "
                "correlacionar origem, destino, porta, processo e volume."
            ),
            expected_evidence=(
                network_values
                if network_values
                else [
                    "Consultas DNS do host",
                    "Conexões externas do processo",
                    "Destinos raros no ambiente",
                ]
            ),
        ),
        HuntingChecklistItem(
            priority="P1",
            data_source="E-mail / navegador / gateway web",
            objective=(
                "Identificar o mecanismo de entrega e outros destinatários."
            ),
            procedure=(
                "Correlacionar o primeiro aparecimento do arquivo com "
                "downloads, anexos, URLs, remetentes e histórico do navegador."
            ),
            expected_evidence=[
                "URL ou mensagem de origem",
                "Remetente e destinatários relacionados",
                "Outros downloads com o mesmo hash ou nome",
            ],
        ),
    ]

    normalized_types = " ".join(
        artifact.file_types
    ).casefold()

    if any(
        marker in normalized_types
        for marker in ("win", "pe32", "exe", "dll")
    ):
        items.append(
            HuntingChecklistItem(
                priority="P1",
                data_source="Windows forensic artifacts",
                objective=(
                    "Validar execução e mecanismos de persistência no Windows."
                ),
                procedure=(
                    "Coletar Prefetch, Amcache, Shimcache, SRUM, Event Logs, "
                    "Run/RunOnce, serviços e tarefas agendadas."
                ),
                expected_evidence=[
                    "Evidência histórica de execução",
                    "Persistência em registro, serviço ou tarefa",
                    "Eventos PowerShell ou criação de processo",
                ],
            )
        )
    elif any(
        marker in normalized_types
        for marker in ("mach-o", "macho", "macos", "osx")
    ):
        items.append(
            HuntingChecklistItem(
                priority="P1",
                data_source="macOS forensic artifacts",
                objective=(
                    "Validar execução e persistência no macOS."
                ),
                procedure=(
                    "Coletar Unified Logs, atributos de quarentena, "
                    "LaunchAgents, LaunchDaemons, login items e cron."
                ),
                expected_evidence=[
                    "com.apple.quarantine e origem do download",
                    "LaunchAgent ou LaunchDaemon criado",
                    "Execução e conexões no Unified Log",
                ],
            )
        )
    elif any(
        marker in normalized_types
        for marker in ("elf", "linux")
    ):
        items.append(
            HuntingChecklistItem(
                priority="P1",
                data_source="Linux forensic artifacts",
                objective=(
                    "Validar execução e persistência no Linux."
                ),
                procedure=(
                    "Coletar journal, auditd, systemd units, cron, shell "
                    "history e arquivos alterados em diretórios temporários."
                ),
                expected_evidence=[
                    "Execução registrada em auditd ou journal",
                    "Unit systemd ou entrada cron criada",
                    "Binários ou scripts em diretórios temporários",
                ],
            )
        )

    return items


def _limitations(result: TriageResult) -> list[str]:
    limitations = list(result.source_errors)

    if result.analysis:
        limitations.extend(result.analysis.gaps)
        limitations.extend(result.analysis.analytic_caveats)

    if result.status == "partial":
        limitations.append(
            "A coleta foi parcial; conclusões podem mudar quando as "
            "fontes indisponíveis forem consultadas novamente."
        )

    if not result.observables:
        limitations.append(
            "Nenhum observável relacionado foi obtido nesta execução."
        )

    if not result.analysis or not result.analysis.ttps:
        limitations.append(
            "A ausência de TTPs pode refletir falta de telemetria de "
            "sandbox e não ausência de comportamento malicioso."
        )

    limitations.extend(
        [
            (
                "Atribuição de família é uma hipótese analítica e não "
                "equivale à atribuição de ator ou campanha."
            ),
            (
                "IPs, domínios e URLs relacionados não são tratados como "
                "C2 confirmado sem corroboração adicional."
            ),
            (
                "Revalide observáveis de infraestrutura antes de bloqueios "
                "permanentes, pois endereços podem ser compartilhados ou "
                "reatribuídos."
            ),
        ]
    )

    return _unique(limitations)


def build_cti_report(result: TriageResult) -> CTIReport:
    """Cria um relatório CTI rastreável sem nova chamada de GenAI."""

    valid_evidence_ids = {
        evidence.id
        for evidence in result.evidence
    }

    artifact = _artifact_profile(result)
    families = _grounded_families(
        result,
        valid_evidence_ids,
    )
    ttps = _grounded_ttps(
        result,
        valid_evidence_ids,
    )
    infrastructure = _infrastructure(
        result,
        valid_evidence_ids,
    )

    if result.analysis is None:
        verdict = "unknown"
        confidence = "low"
        summary = (
            "A triagem não produziu uma avaliação analítica. Consulte as "
            "evidências e erros de fonte antes de tomar ações de bloqueio."
        )
        hypotheses: list[str] = []
        recommendations: list[Recommendation] = []
    else:
        verdict = result.analysis.verdict
        confidence = result.analysis.confidence
        summary = result.analysis.executive_summary
        hypotheses = result.analysis.hunting_hypotheses
        recommendations = result.analysis.recommendations

    methodology = _unique(
        list(result.methodology)
        + [
            "Planejamento orientado por PIRs.",
            "Coleta multiorigem em VirusTotal e MalwareBazaar.",
            "Normalização de observáveis e evidências com IDs rastreáveis.",
            "Análise determinística antes da avaliação opcional por GenAI.",
            "Grounding de famílias, TTPs e infraestrutura nas evidências.",
            "Expressão explícita de confiança, lacunas e hipóteses.",
        ]
    )

    return CTIReport(
        report_id=f"CTI-{result.scan_id}",
        scan_id=result.scan_id,
        title=(
            "Relatório de Inteligência de Ameaças — "
            f"{result.requested_hash[:12]}"
        ),
        generated_at=datetime.now(timezone.utc),
        classification="TLP:CLEAR",
        status=result.status,
        executive_summary=summary,
        verdict=verdict,
        confidence=confidence,
        artifact=artifact,
        providers=[
            ReportProviderSummary(
                provider=provider.provider,
                status=provider.status,
                fetched_at=provider.fetched_at,
                error=provider.error,
            )
            for provider in result.providers
        ],
        intelligence_requirements=_pir_assessments(
            result,
            families,
            ttps,
            infrastructure,
        ),
        family_candidates=families,
        observables=result.observables,
        infrastructure=infrastructure,
        ttps=ttps,
        hunting_hypotheses=hypotheses,
        hunting_checklist=_hunting_checklist(
            artifact,
            result.observables,
        ),
        recommendations=recommendations,
        evidence=result.evidence,
        limitations=_limitations(result),
        methodology=methodology,
        analysis_execution=result.analysis_execution,
    )


def _json_pretty(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=str,
    )


def render_cti_report_html(report: CTIReport) -> str:
    """Renderiza HTML com autoescape habilitado contra XSS."""

    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIRECTORY)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "xml"),
            default_for_string=True,
        ),
    )
    environment.filters["json_pretty"] = _json_pretty

    template = environment.get_template("report.html")

    return template.render(report=report)
