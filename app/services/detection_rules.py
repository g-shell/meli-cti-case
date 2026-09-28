"""
Geração de regras de detecção a partir de um scan.

- Regras de IOC (sempre que houver indicadores): YARA por hash e consulta
  KQL do Elastic Security para hashes e rede.
- Regras de comportamento (somente quando a sandbox observou o comportamento
  na plataforma do artefato): Sigma + EQL.

As regras são geradas automaticamente e devem ser validadas em ambiente de
teste antes da produção. Valores externos são escapados para cada linguagem.
"""

from __future__ import annotations

import re
import uuid

from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Iterable

from app.models import (
    ArtifactProfile,
    DetectionRule,
    Evidence,
    TriageResult,
)
from app.services.context_filters import (
    detect_artifact_platform,
    has_clean_reputation,
    incompatible_evidence_ids,
    is_known_infrastructure,
)


BEHAVIOR_KINDS = {
    "sandbox_command",
    "file_written",
    "registry_key_set",
}

SHA256 = re.compile(r"^[0-9a-f]{64}$")
RANDOM_LABEL = re.compile(r"^com\.[A-Za-z0-9_.-]{1,64}\.[a-z]{16}\.plist$")
RANDOM_LABEL_REGEX = r"com\.[A-Za-z0-9_.-]{1,64}\.[a-z]{16}\.plist"
PLIST_PATH = re.compile(
    r"(/[^\s\"']*/Library/Launch(?:Agents|Daemons)/[^\s\"'/]+\.plist)"
)
RUN_KEY = re.compile(r"\\currentversion\\run(once)?(\\|$)", re.IGNORECASE)
ENCODED_POWERSHELL = re.compile(
    r"powershell(\.exe)?[\"']?\s+.*-(e|en|enc|encodedcommand)\b",
    re.IGNORECASE,
)

NAMESPACE = uuid.UUID("8b1f0c52-7d0e-4c1a-9a55-3f0a7c9e2d10")


def _uuid(scan_id: str, name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{scan_id}:{name}"))


def _quote(value: str) -> str:
    """String entre aspas duplas para YARA, KQL, EQL e YAML."""

    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _identifier(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _behavior_evidence(result: TriageResult) -> list[Evidence]:
    noise = incompatible_evidence_ids(result.evidence)

    return [
        item
        for item in result.evidence
        if item.kind in BEHAVIOR_KINDS
        and item.id not in noise
        and isinstance(item.value, str)
    ]


def _file_hashes(result: TriageResult, artifact: ArtifactProfile) -> list[str]:
    hashes = [artifact.hashes.get("sha256", "")]

    hashes.extend(
        observable.value.lower()
        for observable in result.observables
        if observable.type == "hash"
    )

    # Arquivo pai (MalwareBazaar dropped_by) e demais artefatos da cadeia.
    hashes.extend(
        str(item.value.get("sha256") or "").lower()
        for item in result.evidence
        if item.kind == "related_family_label" and isinstance(item.value, dict)
    )

    return [value for value in _unique(hashes) if SHA256.match(value)]


def _yara_hash_rule(
    result: TriageResult,
    artifact: ArtifactProfile,
    hashes: list[str],
    generated: str,
) -> DetectionRule:
    name = f"CTI_Hashes_{_identifier(result.scan_id[:8])}"
    conditions = "\n        or ".join(
        f"hash.sha256(0, filesize) == {_quote(value)}" for value in hashes
    )
    content = (
        'import "hash"\n\n'
        f"rule {name}\n"
        "{\n"
        "    meta:\n"
        f"        description = {_quote('Amostra e arquivos relacionados do scan ' + result.scan_id)}\n"
        f"        reference = {_quote('CTI-' + result.scan_id)}\n"
        f"        date = {_quote(generated)}\n"
        '        basis = "ioc"\n'
        "    condition:\n"
        f"        {conditions}\n"
        "}\n"
    )

    return DetectionRule(
        rule_id=f"DET-{result.scan_id[:8]}-01",
        title="Arquivos da amostra e da cadeia por hash",
        language="yara",
        platform="YARA (EDR, varredura de disco, gateway de e-mail)",
        basis="ioc",
        hypothesis=(
            "Qualquer correspondência indica que o host armazenou ou recebeu a "
            "amostra ou um artefato da mesma cadeia. Investigue a origem do "
            "arquivo, o processo que o gravou e se houve execução."
        ),
        rationale=(
            f"{len(hashes)} hash(es) SHA-256: amostra analisada e arquivos da "
            "cadeia (dropados e arquivo pai) coletados no scan."
        ),
        content=content,
    )


def _kql_ioc_rule(
    result: TriageResult,
    artifact: ArtifactProfile,
    hashes: list[str],
) -> DetectionRule | None:
    network = [
        observable
        for observable in result.observables
        if observable.type in {"ip", "domain", "url"}
        and not is_known_infrastructure(observable)
    ]

    ips = _unique(item.value for item in network if item.type == "ip")
    domains = _unique(item.value.lower() for item in network if item.type == "domain")
    urls = _unique(item.value for item in network if item.type == "url")

    clauses: list[str] = []

    def group(field: str, values: list[str]) -> None:
        if not values:
            return

        if len(values) == 1:
            clauses.append(f"{field} : {_quote(values[0])}")
            return

        joined = " or\n    ".join(_quote(value) for value in values)
        clauses.append(f"{field} : (\n    {joined}\n  )")

    group("file.hash.sha256", hashes)
    group("file.hash.md5", _unique([artifact.hashes.get("md5", "")]))
    group("destination.ip", ips)
    group("dns.question.name", domains)
    group("url.domain", domains)
    group("url.full", urls)

    if not clauses:
        return None

    clean_network = sum(1 for item in network if has_clean_reputation(item))
    reputation_note = (
        f" {clean_network} indicador(es) de rede sem detecção maliciosa: usar para "
        "correlação, não para bloqueio."
        if clean_network
        else ""
    )

    return DetectionRule(
        rule_id=f"DET-{result.scan_id[:8]}-02",
        title="Busca de IOCs (hashes e rede) no Elastic Security",
        language="kql",
        platform="Elastic Security — Custom query / Timeline",
        basis="ioc",
        hypothesis=(
            "Hosts com correspondência tiveram contato com a amostra ou com a "
            "infraestrutura observada. Priorize eventos de processo e arquivo; "
            "para rede, correlacione com o processo de origem antes de bloquear."
        ),
        rationale=(
            f"{len(hashes)} hash(es), {len(ips)} IP(s), {len(domains)} domínio(s) "
            f"e {len(urls)} URL(s). Infraestrutura de SO/CDN excluída."
            + reputation_note
        ),
        content="\n  or ".join(clauses) + "\n",
    )


def _sigma(
    scan_id: str,
    name: str,
    title: str,
    description: str,
    product: str,
    category: str,
    detection: str,
    tags: list[str],
    level: str,
    generated: str,
) -> str:
    tag_lines = "".join(f"    - {tag}\n" for tag in tags)

    return (
        f"title: {title}\n"
        f"id: {_uuid(scan_id, name)}\n"
        "status: experimental\n"
        f"description: {_quote(description)}\n"
        "references:\n"
        f"    - {_quote('CTI-' + scan_id)}\n"
        "author: CTI Triage (gerada automaticamente)\n"
        f"date: {generated}\n"
        "tags:\n"
        f"{tag_lines}"
        "logsource:\n"
        f"    product: {product}\n"
        f"    category: {category}\n"
        "detection:\n"
        f"{detection}"
        "falsepositives:\n"
        "    - Validar em ambiente de teste antes da produção.\n"
        f"level: {level}\n"
    )


def _launch_agent_rules(
    result: TriageResult,
    evidence: list[Evidence],
    generated: str,
    counter: list[int],
) -> list[DetectionRule]:
    paths: dict[str, list[str]] = {}

    for item in evidence:
        for match in PLIST_PATH.findall(item.value):
            paths.setdefault(match, []).append(item.id)

    if not paths:
        return []

    names = _unique(PurePosixPath(path).name for path in paths)
    evidence_ids = _unique(eid for ids in paths.values() for eid in ids)
    random_label = any(RANDOM_LABEL.match(name) for name in names)

    if random_label:
        sigma_selection = (
            f"        TargetFilename|re: {_quote('.*/Library/LaunchAgents/' + RANDOM_LABEL_REGEX)}\n"
        )
        eql_name = f'file.name regex~ {_quote(RANDOM_LABEL_REGEX)}'
        label_note = "padrão com.<usuário>.<16 letras>.plist observado"
    else:
        quoted = ", ".join(_quote(name) for name in names)
        sigma_selection = "        TargetFilename|endswith:\n" + "".join(
            f"            - {_quote('/' + name)}\n" for name in names
        )
        eql_name = f"file.name in ({quoted})"
        label_note = "nome(s) de plist observados"

    rules: list[DetectionRule] = []

    counter[0] += 1
    rules.append(
        DetectionRule(
            rule_id=f"DET-{result.scan_id[:8]}-{counter[0]:02d}",
            title="Persistência: criação de LaunchAgent (Sigma)",
            language="sigma",
            platform="Sigma — converter para Elastic, Splunk ou Sentinel",
            basis="behavior",
            hypothesis=(
                "Um alerta indica persistência instalada no Mac. Verifique o "
                "ProgramArguments do plist, o binário ou script apontado e o "
                "processo que gravou o arquivo."
            ),
            rationale=f"Sandbox registrou gravação/carga de plist ({label_note}).",
            mitre_attack=["T1543.001"],
            evidence_ids=evidence_ids,
            content=_sigma(
                result.scan_id,
                "launchagent_creation",
                "LaunchAgent Criado com Padrão da Amostra",
                "Criação de plist em LaunchAgents com o padrão observado na amostra.",
                "macos",
                "file_event",
                "    selection:\n" + sigma_selection + "    condition: selection\n",
                ["attack.persistence", "attack.t1543.001"],
                "high",
                generated,
            ),
        )
    )

    counter[0] += 1
    rules.append(
        DetectionRule(
            rule_id=f"DET-{result.scan_id[:8]}-{counter[0]:02d}",
            title="Persistência: criação de LaunchAgent (EQL)",
            language="eql",
            platform="Elastic Security — Event Correlation (Elastic Defend)",
            basis="behavior",
            hypothesis=(
                "Mesma hipótese da regra Sigma, pronta para Elastic Defend. "
                "Combine com a execução de launchctl no mesmo host."
            ),
            rationale=f"Sandbox registrou gravação/carga de plist ({label_note}).",
            mitre_attack=["T1543.001"],
            evidence_ids=evidence_ids,
            content=(
                'file where host.os.type == "macos" and\n'
                '  event.type in ("creation", "change") and\n'
                '  file.path : ("*/Library/LaunchAgents/*", "*/Library/LaunchDaemons/*") and\n'
                f"  {eql_name}\n"
            ),
        )
    )

    launchctl_ids = [
        item.id
        for item in evidence
        if item.kind == "sandbox_command" and "launchctl" in item.value.lower()
    ]

    if launchctl_ids:
        label = (
            f"process.args regex~ {_quote('.*' + RANDOM_LABEL_REGEX)}"
            if random_label
            else "process.args : (" + ", ".join(_quote("*" + name) for name in names) + ")"
        )
        counter[0] += 1
        rules.append(
            DetectionRule(
                rule_id=f"DET-{result.scan_id[:8]}-{counter[0]:02d}",
                title="Persistência: launchctl carregando o LaunchAgent (EQL)",
                language="eql",
                platform="Elastic Security — Event Correlation (Elastic Defend)",
                basis="behavior",
                hypothesis=(
                    "Indica ativação da persistência. Se ocorrer logo após a "
                    "criação do plist no mesmo host, trate como infecção provável."
                ),
                rationale="Sandbox registrou launchctl load/bootstrap do plist.",
                mitre_attack=["T1543.001", "T1059.004"],
                evidence_ids=launchctl_ids,
                content=(
                    'process where host.os.type == "macos" and event.type == "start" and\n'
                    '  process.name == "launchctl" and process.args in ("load", "bootstrap") and\n'
                    f"  {label}\n"
                ),
            )
        )

    return rules


def _killall_terminal_rule(
    result: TriageResult,
    evidence: list[Evidence],
    generated: str,
    counter: list[int],
) -> list[DetectionRule]:
    ids = [
        item.id
        for item in evidence
        if item.kind == "sandbox_command"
        and re.search(r"killall\s+terminal", item.value, re.IGNORECASE)
    ]

    if not ids:
        return []

    counter[0] += 1

    return [
        DetectionRule(
            rule_id=f"DET-{result.scan_id[:8]}-{counter[0]:02d}",
            title="Ocultação: Terminal encerrado por shell (Sigma)",
            language="sigma",
            platform="Sigma — converter para Elastic, Splunk ou Sentinel",
            basis="behavior",
            hypothesis=(
                "Em golpes do tipo ClickFix o malware fecha o Terminal onde a "
                "vítima colou o comando. Revise o histórico de shell e o "
                "download que antecedeu o evento."
            ),
            rationale="Sandbox registrou 'killall Terminal' iniciado por shell.",
            mitre_attack=["T1564"],
            evidence_ids=ids,
            content=_sigma(
                result.scan_id,
                "killall_terminal",
                "Terminal Encerrado por Shell",
                "killall Terminal iniciado por sh, bash ou zsh.",
                "macos",
                "process_creation",
                (
                    "    selection:\n"
                    "        Image|endswith: '/killall'\n"
                    "        CommandLine|contains: 'Terminal'\n"
                    "        ParentImage|endswith:\n"
                    "            - '/sh'\n"
                    "            - '/bash'\n"
                    "            - '/zsh'\n"
                    "    condition: selection\n"
                ),
                ["attack.defense-evasion", "attack.t1564"],
                "medium",
                generated,
            ),
        )
    ]


def _windows_rules(
    result: TriageResult,
    evidence: list[Evidence],
    generated: str,
    counter: list[int],
) -> list[DetectionRule]:
    rules: list[DetectionRule] = []

    encoded = [
        item.id
        for item in evidence
        if item.kind == "sandbox_command" and ENCODED_POWERSHELL.search(item.value)
    ]

    if encoded:
        counter[0] += 1
        rules.append(
            DetectionRule(
                rule_id=f"DET-{result.scan_id[:8]}-{counter[0]:02d}",
                title="Execução: PowerShell com comando codificado (EQL)",
                language="eql",
                platform="Elastic Security — Event Correlation (Elastic Defend)",
                basis="behavior",
                hypothesis=(
                    "Comandos codificados ocultam o script executado. Decodifique "
                    "o argumento e verifique o processo pai."
                ),
                rationale="Sandbox registrou PowerShell com -EncodedCommand.",
                mitre_attack=["T1059.001", "T1027"],
                evidence_ids=encoded,
                content=(
                    'process where host.os.type == "windows" and event.type == "start" and\n'
                    '  process.name : ("powershell.exe", "pwsh.exe") and\n'
                    '  process.args : ("-e", "-en", "-enc", "-encodedcommand", "-EncodedCommand")\n'
                ),
            )
        )

    run_keys = [
        item
        for item in evidence
        if item.kind == "registry_key_set" and RUN_KEY.search(item.value)
    ]

    if run_keys:
        values = _unique(item.value.rstrip("\\").rsplit("\\", 1)[-1] for item in run_keys)
        quoted = ", ".join(_quote(value) for value in values)
        counter[0] += 1
        rules.append(
            DetectionRule(
                rule_id=f"DET-{result.scan_id[:8]}-{counter[0]:02d}",
                title="Persistência: valor na chave Run (EQL)",
                language="eql",
                platform="Elastic Security — Event Correlation (Elastic Defend)",
                basis="behavior",
                hypothesis=(
                    "O valor na chave Run executa o malware a cada logon. Verifique "
                    "o caminho gravado no valor e o processo que o criou."
                ),
                rationale="Sandbox registrou alteração em chave Run/RunOnce.",
                mitre_attack=["T1547.001"],
                evidence_ids=[item.id for item in run_keys],
                content=(
                    'registry where host.os.type == "windows" and\n'
                    '  registry.path : ("*\\\\CurrentVersion\\\\Run\\\\*", "*\\\\CurrentVersion\\\\RunOnce\\\\*") and\n'
                    f"  registry.value : ({quoted})\n"
                ),
            )
        )

    return rules


def build_detection_rules(
    result: TriageResult,
    artifact: ArtifactProfile,
) -> list[DetectionRule]:
    """Gera as regras do scan: IOCs primeiro, depois comportamento."""

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rules: list[DetectionRule] = []

    hashes = _file_hashes(result, artifact)

    if hashes:
        rules.append(_yara_hash_rule(result, artifact, hashes, generated))

    kql = _kql_ioc_rule(result, artifact, hashes)
    if kql is not None:
        rules.append(kql)

    counter = [len(rules)]
    evidence = _behavior_evidence(result)
    platform = detect_artifact_platform(result.evidence)

    if platform in (None, "macos"):
        rules.extend(_launch_agent_rules(result, evidence, generated, counter))
        rules.extend(_killall_terminal_rule(result, evidence, generated, counter))

    if platform in (None, "windows"):
        rules.extend(_windows_rules(result, evidence, generated, counter))

    return rules
