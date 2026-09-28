from __future__ import annotations

import ipaddress
import json
import re

from typing import Any, Literal, TypeAlias

from app.models import Evidence, Observable


Platform: TypeAlias = Literal[
    "windows",
    "macos",
    "linux",
]

# Sandboxes multiplataforma (ex.: VirusTotal) tentam abrir a amostra em
# ambientes incompatíveis. Um Mach-O "executado" em Windows gera ruído
# como rundll32 OpenAs_RunDLL, Acrobat Reader e chamadas WinINet.
WINDOWS_MARKERS = re.compile(
    r"(^|[\s\"'])[a-z]:\\"
    r"|\\windows\\"
    r"|\\appdata\\"
    r"|\\sessions\\\d+\\basenamedobjects"
    r"|\\program files"
    r"|\.(exe|dll|sys|bat|ps1)\b"
    r"|\bhk(lm|cu|ey_[a-z_]+)\b"
    r"|\b(kernel32|advapi32|wininet|shell32|ntdll|user32"
    r"|ws2_32|urlmon|ole32|crypt32|winhttp)\.",
    re.IGNORECASE,
)

MACOS_MARKERS = re.compile(
    r"(^|[\s\"'~])(/private)?/users/"
    r"|~/library/"
    r"|(^|[\s\"'])(/private/var/root|/private/var|/system)?/library/"
    r"|/applications/"
    r"|/usr/libexec/"
    r"|\blaunchctl\b"
    r"|\bxpcproxy\b"
    r"|\bosascript\b"
    r"|\bdscl\b"
    r"|\.plist\b"
    r"|\bcom\.apple\.",
    re.IGNORECASE,
)

LINUX_MARKERS = re.compile(
    r"(^|[\s\"'])/proc/"
    r"|(^|[\s\"'])/etc/(systemd|cron|init\.d|ld\.so)"
    r"|\bsystemctl\b"
    r"|\bcrontab\b",
    re.IGNORECASE,
)

FILE_TYPE_PLATFORMS: tuple[tuple[str, Platform], ...] = (
    ("mach-o", "macos"),
    ("macho", "macos"),
    ("elf", "linux"),
    ("pe32", "windows"),
    ("win32", "windows"),
    ("win64", "windows"),
    ("ms-dos", "windows"),
    ("msi", "windows"),
)

# Infraestrutura de fornecedores de SO e CDNs contatada rotineiramente
# por qualquer processo em sandbox. Não é allowlist de bloqueio: provedores
# de nuvem genéricos (AWS, Azure, GCP) ficam de fora de propósito, pois
# também hospedam C2.
KNOWN_INFRASTRUCTURE_NETWORKS: tuple[tuple[str, str], ...] = (
    ("17.0.0.0/8", "Apple"),
    ("151.101.0.0/16", "Fastly CDN"),
    ("199.232.0.0/16", "Fastly CDN"),
    ("2.16.0.0/13", "Akamai"),
    ("23.0.0.0/12", "Akamai"),
    ("23.32.0.0/11", "Akamai"),
    ("23.192.0.0/11", "Akamai"),
    ("96.6.0.0/15", "Akamai"),
    ("104.64.0.0/10", "Akamai"),
)

KNOWN_INFRASTRUCTURE_DOMAINS: tuple[tuple[str, str], ...] = (
    ("apple.com", "Apple"),
    ("icloud.com", "Apple"),
    ("mzstatic.com", "Apple"),
    ("cdn-apple.com", "Apple"),
    ("apple-cloudkit.com", "Apple"),
    ("apple.map.fastly.net", "Apple via Fastly CDN"),
    ("microsoft.com", "Microsoft"),
    ("windowsupdate.com", "Microsoft"),
    ("msftncsi.com", "Microsoft"),
    ("msftconnecttest.com", "Microsoft"),
    ("digicert.com", "DigiCert (OCSP/CRL)"),
)

_PARSED_NETWORKS = tuple(
    (ipaddress.ip_network(cidr), owner)
    for cidr, owner in KNOWN_INFRASTRUCTURE_NETWORKS
)


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except (TypeError, ValueError):
        return str(value)


def detect_artifact_platform(
    evidence: list[Evidence],
) -> Platform | None:
    """
    Identifica a plataforma alvo pelo tipo de arquivo informado
    pelos provedores. Retorna None quando não houver consenso.
    """
    platforms: set[Platform] = set()

    for item in evidence:
        if item.kind not in {
            "file_metadata",
            "sample_metadata",
        }:
            continue

        if not isinstance(item.value, dict):
            continue

        for key in (
            "type_description",
            "file_type",
            "type_tag",
        ):
            raw = item.value.get(key)

            if not isinstance(raw, str):
                continue

            normalized = raw.casefold()

            for needle, platform in FILE_TYPE_PLATFORMS:
                if needle in normalized:
                    platforms.add(platform)
                    break

    if len(platforms) == 1:
        return next(iter(platforms))

    return None


def evidence_platform(
    evidence: Evidence,
) -> Platform | None:
    """
    Infere a plataforma em que a evidência foi produzida.

    Retorna None quando não há marcadores ou quando os marcadores
    são ambíguos, preservando a evidência.
    """
    text = _as_text(evidence.value)

    matches: set[Platform] = set()

    if WINDOWS_MARKERS.search(text):
        matches.add("windows")

    if MACOS_MARKERS.search(text):
        matches.add("macos")

    if LINUX_MARKERS.search(text):
        matches.add("linux")

    if len(matches) == 1:
        return next(iter(matches))

    return None


def incompatible_evidence_ids(
    evidence: list[Evidence],
    artifact_platform: Platform | None = None,
) -> set[str]:
    """
    IDs de evidências produzidas numa plataforma diferente da
    plataforma alvo da amostra (ruído de sandbox).
    """
    if artifact_platform is None:
        artifact_platform = detect_artifact_platform(
            evidence
        )

    if artifact_platform is None:
        return set()

    output: set[str] = set()

    for item in evidence:
        platform = evidence_platform(item)

        if platform is None or platform == artifact_platform:
            continue

        # macOS também possui cron e /etc; só o inverso é ruído.
        if (
            artifact_platform == "macos"
            and platform == "linux"
        ):
            continue

        output.add(item.id)

    return output


def known_infrastructure_owner(
    observable_type: str,
    value: str,
) -> str | None:
    """
    Retorna o operador quando o IP ou domínio pertence a fornecedor
    de SO/CDN conhecido.
    """
    cleaned = value.strip().casefold().rstrip(".")

    if observable_type == "ip":
        try:
            address = ipaddress.ip_address(cleaned)
        except ValueError:
            return None

        for network, owner in _PARSED_NETWORKS:
            if (
                address.version == network.version
                and address in network
            ):
                return owner

        return None

    if observable_type == "domain":
        for suffix, owner in KNOWN_INFRASTRUCTURE_DOMAINS:
            if (
                cleaned == suffix
                or cleaned.endswith(f".{suffix}")
            ):
                return owner

    return None


def is_known_infrastructure(
    observable: Observable,
) -> bool:
    if observable.context.get("known_infrastructure"):
        return True

    return (
        known_infrastructure_owner(
            observable.type,
            observable.value,
        )
        is not None
    )


def has_clean_reputation(
    observable: Observable,
) -> bool:
    """
    True somente quando há estatísticas de reputação e nenhuma
    detecção maliciosa. Ausência de dados não é reputação limpa.
    """
    stats = observable.context.get(
        "last_analysis_stats"
    )

    if not isinstance(stats, dict):
        return False

    try:
        return int(stats.get("malicious", 0)) == 0
    except (TypeError, ValueError):
        return False
