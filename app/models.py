from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator


HASH_LENGTHS: dict[int, Literal["md5", "sha1", "sha256"]] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}

ProviderName: TypeAlias = Literal[
    "virustotal",
    "malwarebazaar",
]

ProviderStatus: TypeAlias = Literal[
    "ok",
    "not_found",
    "not_configured",
    "forbidden",
    "rate_limited",
    "error",
]

ObservableType: TypeAlias = Literal[
    "hash",
    "ip",
    "domain",
    "url",
    "filename",
    "mutex",
    "registry",
    "other",
]

Confidence: TypeAlias = Literal[
    "low",
    "medium",
    "high",
]


class TriageRequest(BaseModel):
    """Dados recebidos pela API para iniciar uma triagem."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "hash": (
                    "7a8fc48ce4df4448b91a1e6b66410cca"
                    "6993ac072cb12860b9cfa6438b25ed8e"
                ),
                "providers": [
                    "virustotal",
                    "malwarebazaar",
                ],
                "use_genai": False,
                "force_refresh": False,
            }
        }
    )

    hash: str = Field(
        ...,
        description=(
            "Hash MD5, SHA-1 ou SHA-256 que será investigado."
        ),
    )
    providers: list[ProviderName] = Field(
        default_factory=lambda: [
            "virustotal",
            "malwarebazaar",
        ]
    )
    use_genai: bool = True
    force_refresh: bool = False

    @field_validator("hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        value = value.strip().lower()

        if len(value) not in HASH_LENGTHS:
            raise ValueError(
                "hash must be MD5, SHA-1 or SHA-256"
            )

        if any(
            character not in "0123456789abcdef"
            for character in value
        ):
            raise ValueError(
                "hash must contain only hexadecimal characters"
            )

        return value

    @field_validator("providers")
    @classmethod
    def validate_providers(
        cls,
        value: list[ProviderName],
    ) -> list[ProviderName]:
        if not value:
            raise ValueError(
                "at least one provider is required"
            )

        return list(dict.fromkeys(value))


class Observable(BaseModel):
    """Indicador ou artefato encontrado durante a análise."""

    type: ObservableType
    value: str
    source: str
    relationship: str | None = None
    confidence: Confidence = "medium"
    context: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Evidência utilizada para sustentar uma conclusão."""

    id: str
    source: str
    kind: str
    value: Any
    observed: bool = True


class TTPAssessment(BaseModel):
    """Técnica MITRE ATT&CK identificada na amostra."""

    technique_id: str
    technique_name: str
    confidence: Confidence
    evidence_ids: list[str] = Field(default_factory=list)
    rationale: str


class FamilyCandidate(BaseModel):
    """Possível família de malware."""

    family: str
    confidence: Confidence
    supporting_evidence_ids: list[str] = Field(
        default_factory=list
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list
    )
    rationale: str


class Recommendation(BaseModel):
    """Recomendação defensiva e sua validação."""

    priority: Literal["P0", "P1", "P2", "P3"]
    phase: Literal[
        "containment",
        "eradication",
        "recovery",
        "hardening",
        "detection",
    ]
    action: str
    rationale: str
    d3fend_id: str | None = None
    validation: str


class LLMAnalysis(BaseModel):
    """Contrato comum da análise determinística e da GenAI."""

    verdict: Literal[
        "malicious",
        "suspicious",
        "benign",
        "unknown",
    ]
    confidence: Confidence
    executive_summary: str
    family_candidates: list[FamilyCandidate] = Field(
        default_factory=list
    )
    ttps: list[TTPAssessment] = Field(default_factory=list)
    c2_assessment: list[Observable] = Field(
        default_factory=list
    )
    hunting_hypotheses: list[str] = Field(
        default_factory=list
    )
    recommendations: list[Recommendation] = Field(
        default_factory=list
    )
    gaps: list[str] = Field(default_factory=list)
    analytic_caveats: list[str] = Field(default_factory=list)


class GenAIUsage(BaseModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)


class AnalysisExecution(BaseModel):
    requested: bool = False
    attempted: bool = False
    succeeded: bool = False
    engine: Literal[
        "deterministic",
        "genai",
        "deterministic_fallback",
    ] = "deterministic"
    provider: Literal["openai", "anthropic"] | None = None
    model: str | None = None
    fallback_used: bool = False
    error_code: str | None = None
    usage: GenAIUsage = Field(default_factory=GenAIUsage)


class ProviderResult(BaseModel):
    """Resultado retornado por um provedor externo."""

    provider: str
    status: ProviderStatus
    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class TriageResult(BaseModel):
    """Resultado completo de uma triagem."""

    scan_id: str
    requested_hash: str
    hash_type: Literal["md5", "sha1", "sha256"]
    created_at: datetime
    completed_at: datetime | None = None
    status: Literal[
        "running",
        "completed",
        "partial",
        "failed",
    ]
    providers: list[ProviderResult] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    analysis: LLMAnalysis | None = None
    analysis_execution: AnalysisExecution = Field(
        default_factory=AnalysisExecution
    )
    source_errors: list[str] = Field(default_factory=list)
    raw_data_retained: bool = True
    methodology: list[str] = Field(default_factory=list)


class ObservableSearchRequest(BaseModel):
    """Contrato de pesquisa para IP, domínio, URL ou hash."""

    value: str = Field(min_length=1, max_length=2048)
    type: Literal[
        "auto",
        "hash",
        "ip",
        "domain",
        "url",
    ] = "auto"


class ReportProviderSummary(BaseModel):
    provider: str
    status: ProviderStatus
    fetched_at: datetime
    error: str | None = None


class ArtifactProfile(BaseModel):
    requested_hash: str
    hash_type: Literal["md5", "sha1", "sha256"]
    hashes: dict[str, str] = Field(default_factory=dict)
    filenames: list[str] = Field(default_factory=list)
    file_types: list[str] = Field(default_factory=list)
    file_sizes: list[int] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None


class PIRAssessment(BaseModel):
    pir_id: str
    question: str
    status: Literal[
        "answered",
        "partially_answered",
        "unanswered",
    ]
    confidence: Confidence
    assessment: str
    evidence_ids: list[str] = Field(default_factory=list)


class InfrastructureAssessment(BaseModel):
    observable: Observable
    classification: Literal[
        "known_infrastructure",
        "related_infrastructure",
        "observed_network_activity",
        "candidate_c2",
        "confirmed_c2",
    ]
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)


class HuntingChecklistItem(BaseModel):
    priority: Literal["P0", "P1", "P2", "P3"]
    data_source: str
    objective: str
    procedure: str
    expected_evidence: list[str] = Field(default_factory=list)


class DetectionRule(BaseModel):
    """Regra de detecção gerada a partir dos IOCs ou do comportamento do scan."""

    rule_id: str
    title: str
    language: Literal["yara", "sigma", "kql", "eql"]
    platform: str
    basis: Literal["ioc", "behavior"]
    hypothesis: str
    rationale: str
    mitre_attack: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    content: str


class CTIReport(BaseModel):
    """Relatório operacional construído a partir do TriageResult."""

    report_id: str
    scan_id: str
    title: str
    generated_at: datetime
    classification: Literal[
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:RED",
    ] = "TLP:CLEAR"
    status: Literal[
        "running",
        "completed",
        "partial",
        "failed",
    ]
    executive_summary: str
    verdict: Literal[
        "malicious",
        "suspicious",
        "benign",
        "unknown",
    ]
    confidence: Confidence
    artifact: ArtifactProfile
    providers: list[ReportProviderSummary] = Field(
        default_factory=list
    )
    intelligence_requirements: list[PIRAssessment] = Field(
        default_factory=list
    )
    family_candidates: list[FamilyCandidate] = Field(
        default_factory=list
    )
    observables: list[Observable] = Field(default_factory=list)
    infrastructure: list[InfrastructureAssessment] = Field(
        default_factory=list
    )
    ttps: list[TTPAssessment] = Field(default_factory=list)
    hunting_hypotheses: list[str] = Field(
        default_factory=list
    )
    hunting_checklist: list[HuntingChecklistItem] = Field(
        default_factory=list
    )
    detection_rules: list[DetectionRule] = Field(
        default_factory=list
    )
    recommendations: list[Recommendation] = Field(
        default_factory=list
    )
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    methodology: list[str] = Field(default_factory=list)
    analysis_execution: AnalysisExecution = Field(
        default_factory=AnalysisExecution
    )


class ObservableOccurrence(BaseModel):
    scan_id: str
    requested_hash: str
    created_at: datetime
    scan_status: Literal[
        "running",
        "completed",
        "partial",
        "failed",
    ]
    observable: Observable


class RepositoryStats(BaseModel):
    total_scans: int = 0
    unique_hashes: int = 0
    status_counts: dict[str, int] = Field(default_factory=dict)
    verdict_counts: dict[str, int] = Field(default_factory=dict)


IndicatorType: TypeAlias = Literal[
    "ip",
    "domain",
]


class PassiveDNSRecord(BaseModel):
    """Resolução histórica (IP → domínio ou domínio → IP)."""

    value: str
    last_resolved: datetime | None = None


class IndicatorEnrichment(BaseModel):
    """Reputação e contexto de um IP ou domínio consultado ao vivo."""

    indicator_type: IndicatorType
    value: str
    provider: str = "virustotal"
    provider_status: ProviderStatus
    fetched_at: datetime
    cached: bool = False
    verdict: Literal[
        "malicious",
        "suspicious",
        "no_detections",
        "unknown",
    ] = "unknown"
    reputation: dict[str, int] = Field(default_factory=dict)
    known_infrastructure: str | None = None
    as_owner: str | None = None
    asn: int | None = None
    country: str | None = None
    network: str | None = None
    registrar: str | None = None
    creation_date: datetime | None = None
    categories: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    dns_records: list[dict[str, str]] = Field(default_factory=list)
    resolutions: list[PassiveDNSRecord] = Field(default_factory=list)
    local_sightings: list[ObservableOccurrence] = Field(
        default_factory=list
    )
