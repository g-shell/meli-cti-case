from __future__ import annotations

from typing import Any, Literal

from app.models import (
    Evidence,
    FamilyCandidate,
    LLMAnalysis,
    Observable,
    ProviderResult,
    Recommendation,
    TTPAssessment,
)
from app.services.normalize import family_consensus


Confidence = Literal["low", "medium", "high"]
Verdict = Literal["malicious", "suspicious", "benign", "unknown"]


def _safe_int(value: Any) -> int:
    """
    Converte valores recebidos dos provedores para inteiro.

    Retorna zero quando o valor estiver ausente ou for inválido.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _feature_rows(
    features: dict[str, Any],
    key: str,
) -> list[dict[str, str]]:
    """
    Obtém linhas válidas de uma feature normalizada.

    Cada linha precisa possuir:
    - value
    - evidence_id
    """
    raw_rows = features.get(key, [])

    if not isinstance(raw_rows, list):
        return []

    rows: list[dict[str, str]] = []

    for raw_row in raw_rows:
        if not isinstance(raw_row, dict):
            continue

        value = raw_row.get("value")
        evidence_id = raw_row.get("evidence_id")

        if not isinstance(value, str):
            continue

        if not isinstance(evidence_id, str):
            continue

        rows.append(
            {
                "value": value,
                "evidence_id": evidence_id,
            }
        )

    return rows


def _matching_evidence_ids(
    rows: list[dict[str, str]],
    needle: str,
) -> list[str]:
    """
    Retorna somente os IDs das evidências que contêm o termo buscado.
    """
    matches = [
        row["evidence_id"]
        for row in rows
        if needle in row["value"].casefold()
    ]

    return list(dict.fromkeys(matches))


def _is_run_key(value: str) -> bool:
    """
    Verifica se o caminho representa uma chave Run ou RunOnce.
    """
    normalized = value.casefold().rstrip("\\")

    return (
        "\\currentversion\\run\\" in normalized
        or "\\currentversion\\runonce\\" in normalized
        or normalized.endswith("\\currentversion\\run")
        or normalized.endswith("\\currentversion\\runonce")
    )


def _build_ttps(
    features: dict[str, Any],
) -> list[TTPAssessment]:
    """
    Mapeia somente comportamentos efetivamente observados.

    Não utiliza nome de família, tag ou detecção de antivírus
    como prova suficiente de um comportamento ATT&CK.
    """
    ttps: list[TTPAssessment] = []

    command_rows = _feature_rows(
        features,
        "commands",
    )

    command_mappings = (
        (
            "powershell",
            "T1059.001",
            "PowerShell",
        ),
        (
            "cmd.exe",
            "T1059.003",
            "Windows Command Shell",
        ),
        (
            "wmic",
            "T1047",
            "Windows Management Instrumentation",
        ),
        (
            "schtasks",
            "T1053.005",
            "Scheduled Task/Job: Scheduled Task",
        ),
        (
            "rundll32",
            "T1218.011",
            "System Binary Proxy Execution: Rundll32",
        ),
    )

    for needle, technique_id, technique_name in command_mappings:
        evidence_ids = _matching_evidence_ids(
            command_rows,
            needle,
        )

        if not evidence_ids:
            continue

        ttps.append(
            TTPAssessment(
                technique_id=technique_id,
                technique_name=technique_name,
                confidence="high",
                evidence_ids=evidence_ids,
                rationale=(
                    "O sandbox registrou comando contendo "
                    f"'{needle}'."
                ),
            )
        )

    registry_rows = _feature_rows(
        features,
        "registry_keys",
    )

    run_key_evidence_ids = [
        row["evidence_id"]
        for row in registry_rows
        if _is_run_key(row["value"])
    ]

    run_key_evidence_ids = list(
        dict.fromkeys(run_key_evidence_ids)
    )

    if run_key_evidence_ids:
        ttps.append(
            TTPAssessment(
                technique_id="T1547.001",
                technique_name=(
                    "Registry Run Keys / Startup Folder"
                ),
                confidence="high",
                evidence_ids=run_key_evidence_ids,
                rationale=(
                    "O sandbox registrou alteração em uma "
                    "chave Run ou RunOnce."
                ),
            )
        )

    return ttps


def _get_detection_stats(
    evidence: list[Evidence],
) -> dict[str, Any]:
    """
    Localiza as estatísticas de detecção do VirusTotal.
    """
    for item in evidence:
        if item.kind != "detection_stats":
            continue

        if isinstance(item.value, dict):
            return item.value

    return {}


def _calculate_verdict(
    providers: list[ProviderResult],
    evidence: list[Evidence],
) -> tuple[Verdict, Confidence]:
    """
    Política inicial de classificação.

    Essa política deverá ser versionada e ajustada conforme
    a experiência do SOC e os falsos positivos encontrados.
    """
    stats = _get_detection_stats(evidence)

    malicious = _safe_int(
        stats.get("malicious")
    )

    suspicious = _safe_int(
        stats.get("suspicious")
    )

    malwarebazaar_found = any(
        provider.provider == "malwarebazaar"
        and provider.status == "ok"
        for provider in providers
    )

    if malicious >= 5:
        return "malicious", "high"

    if malicious > 0 and malwarebazaar_found:
        return "malicious", "high"

    if malicious > 0 or suspicious > 0:
        return "suspicious", "medium"

    if malwarebazaar_found:
        return "suspicious", "medium"

    # Ausência de detecção não significa que o arquivo é benigno.
    return "unknown", "low"


def _build_family_candidates(
    features: dict[str, Any],
) -> list[FamilyCandidate]:
    """
    Converte o consenso produzido pelo normalizador
    para o modelo utilizado na análise.
    """
    candidates: list[FamilyCandidate] = []

    for item in family_consensus(features):
        family = item.get("family")

        if not isinstance(family, str):
            continue

        raw_evidence_ids = item.get(
            "evidence_ids",
            [],
        )

        evidence_ids = (
            [
                evidence_id
                for evidence_id in raw_evidence_ids
                if isinstance(evidence_id, str)
            ]
            if isinstance(raw_evidence_ids, list)
            else []
        )

        independent_sources = _safe_int(
            item.get("independent_sources")
        )

        confidence: Confidence = (
            "high"
            if independent_sources >= 2
            else "low"
        )

        rationale = (
            "Sinais independentes do VirusTotal e "
            "MalwareBazaar são compatíveis."
            if independent_sources >= 2
            else (
                "Identificação baseada em uma única fonte; "
                "requer confirmação comportamental ou "
                "análise de código."
            )
        )

        candidates.append(
            FamilyCandidate(
                family=family,
                confidence=confidence,
                supporting_evidence_ids=evidence_ids,
                contradicting_evidence_ids=[],
                rationale=rationale,
            )
        )

    return candidates


def _build_recommendations() -> list[Recommendation]:
    """
    Recomendações defensivas iniciais relacionadas ao D3FEND.
    """
    return [
        Recommendation(
            priority="P0",
            phase="containment",
            action=(
                "Isolar os endpoints afetados e preservar "
                "memória, processos e conexões antes da remediação."
            ),
            rationale=(
                "Reduz o risco de comunicação externa e "
                "movimentação lateral sem destruir evidências."
            ),
            d3fend_id="D3-NI",
            validation=(
                "Confirmar o isolamento no EDR e verificar "
                "que o host não mantém conexões externas."
            ),
        ),
        Recommendation(
            priority="P0",
            phase="detection",
            action=(
                "Buscar o hash e os observáveis relacionados "
                "no EDR, DNS, proxy, firewall, e-mail e SIEM."
            ),
            rationale=(
                "Amplia a investigação além do equipamento "
                "originalmente identificado."
            ),
            d3fend_id="D3-NTA",
            validation=(
                "Registrar hosts, usuários, processos, "
                "first seen, last seen e prevalência."
            ),
        ),
        Recommendation(
            priority="P1",
            phase="detection",
            action=(
                "Analisar árvore de processos, linha de comando, "
                "processo pai, autoruns, tarefas e serviços."
            ),
            rationale=(
                "Permite identificar execução e persistência "
                "relacionadas ao artefato."
            ),
            d3fend_id="D3-PA",
            validation=(
                "Comparar os processos encontrados com as "
                "evidências e TTPs deste relatório."
            ),
        ),
        Recommendation(
            priority="P1",
            phase="hardening",
            action=(
                "Bloquear somente endereços e domínios "
                "confirmados como maliciosos, com prazo de "
                "expiração e procedimento de rollback."
            ),
            rationale=(
                "Infraestruturas podem ser compartilhadas ou "
                "reatribuídas, causando falsos positivos."
            ),
            d3fend_id="D3-NTF",
            validation=(
                "Testar inicialmente em modo de monitoramento "
                "e revisar falsos positivos."
            ),
        ),
        Recommendation(
            priority="P2",
            phase="detection",
            action=(
                "Submeter o arquivo a análise estática e "
                "dinâmica controlada e criar regras YARA "
                "baseadas em características estáveis."
            ),
            rationale=(
                "Permite produzir detecções mais resilientes "
                "do que um bloqueio baseado somente em hash."
            ),
            d3fend_id="D3-FA",
            validation=(
                "Executar a regra contra um conjunto de "
                "amostras maliciosas e benignas."
            ),
        ),
    ]


def build_deterministic_analysis(
    providers: list[ProviderResult],
    observables: list[Observable],
    evidence: list[Evidence],
    features: dict[str, Any],
) -> LLMAnalysis:
    """
    Constrói uma análise sem depender de GenAI.

    Todas as conclusões são derivadas de regras explícitas
    e de evidências rastreáveis.
    """
    verdict, confidence = _calculate_verdict(
        providers,
        evidence,
    )

    family_candidates = _build_family_candidates(
        features,
    )

    ttps = _build_ttps(
        features,
    )

    network_observables = [
        observable
        for observable in observables
        if observable.type in {
            "ip",
            "domain",
            "url",
        }
    ]

    # Contato de rede não é confirmação automática de C2.
    c2_assessment = [
        observable.model_copy(
            update={
                "confidence": "medium",
            }
        )
        for observable in network_observables
    ]

    provider_summary = ", ".join(
        (
            f"{provider.provider}="
            f"{provider.status}"
        )
        for provider in providers
    )

    gaps: list[str] = []

    unavailable_providers = [
        provider.provider
        for provider in providers
        if provider.status != "ok"
    ]

    if unavailable_providers:
        gaps.append(
            "Fontes indisponíveis ou sem resultado: "
            + ", ".join(unavailable_providers)
            + "."
        )

    if not network_observables:
        gaps.append(
            "Nenhum observável de rede foi retornado; "
            "não é possível estabelecer infraestrutura C2."
        )

    if not _feature_rows(features, "commands"):
        gaps.append(
            "Não há comandos de sandbox disponíveis; "
            "o mapeamento comportamental ATT&CK é limitado."
        )

    if not family_candidates:
        gaps.append(
            "Nenhuma família de malware pôde ser "
            "atribuída de forma defensável."
        )

    return LLMAnalysis(
        verdict=verdict,
        confidence=confidence,
        executive_summary=(
            "Triagem determinística concluída "
            f"({provider_summary}). "
            f"Veredito: {verdict}. "
            "Os observáveis de rede são pistas para "
            "investigação e não representam, isoladamente, "
            "confirmação de servidores C2."
        ),
        family_candidates=family_candidates,
        ttps=ttps,
        c2_assessment=c2_assessment,
        hunting_hypotheses=[
            (
                "Endpoints que executaram o mesmo hash podem "
                "apresentar árvore de processos, arquivos e "
                "mecanismos de persistência semelhantes."
            ),
            (
                "Hosts que se conectaram aos observáveis de "
                "rede próximos ao horário de execução podem "
                "estar relacionados à mesma cadeia de intrusão."
            ),
            (
                "Telemetria de e-mail, navegador ou proxy pode "
                "revelar o vetor de entrega, o nome original "
                "do arquivo e o primeiro usuário afetado."
            ),
        ],
        recommendations=_build_recommendations(),
        gaps=gaps,
        analytic_caveats=[
            (
                "Detecções e rótulos de fornecedores podem "
                "divergir e não equivalem a atribuição definitiva."
            ),
            (
                "Um IP, domínio ou URL contatado não é "
                "automaticamente um servidor C2."
            ),
            (
                "A ausência de resultados em uma fonte não "
                "constitui evidência de que o arquivo seja benigno."
            ),
            (
                "A atribuição de família exige correlação entre "
                "fontes independentes ou evidência comportamental."
            ),
        ],
    )