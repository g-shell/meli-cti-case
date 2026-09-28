from __future__ import annotations

import csv
import io
import sqlite3
import threading

from pathlib import Path
from typing import Any

from app.models import (
    IndicatorEnrichment,
    ObservableOccurrence,
    ObservableType,
    RepositoryStats,
    TriageResult,
)


HISTORY_FIELDS = [
    "scan_id",
    "requested_hash",
    "hash_type",
    "status",
    "verdict",
    "confidence",
    "created_at",
    "completed_at",
    "providers",
    "observable_count",
]


def _safe_csv_cell(value: Any) -> str:
    """
    Evita CSV/Formula Injection quando o arquivo for
    aberto no Excel ou em outra planilha.
    """
    if value is None:
        return ""

    text = str(value)

    dangerous_prefixes = (
        "=",
        "+",
        "-",
        "@",
        "\t",
        "\r",
    )

    if text.startswith(dangerous_prefixes):
        return "'" + text

    return text


class TriageRepository:
    def __init__(
        self,
        database_path: Path,
        csv_path: Path,
    ) -> None:
        self.database_path = database_path
        self.csv_path = csv_path

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.csv_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._lock = threading.Lock()

        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=30.0,
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize(self) -> None:
        """
        Cria a tabela e os índices na primeira execução.
        """
        with self._connect() as connection:
            connection.execute(
                "PRAGMA journal_mode=WAL"
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    requested_hash TEXT NOT NULL,
                    hash_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verdict TEXT,
                    confidence TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    result_json TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_scans_requested_hash
                ON scans(requested_hash)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_scans_created_at
                ON scans(created_at DESC)
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS enrichments (
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    PRIMARY KEY (indicator_type, value)
                )
                """
            )

    def save_enrichment(
        self,
        enrichment: IndicatorEnrichment,
    ) -> None:
        """
        Guarda a última consulta do indicador (cache e histórico).

        Avistamentos locais não são persistidos: são recalculados
        a cada leitura a partir dos scans.
        """
        payload = enrichment.model_copy(
            update={
                "cached": False,
                "local_sightings": [],
            }
        ).model_dump_json()

        with self._lock:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO enrichments (
                        indicator_type,
                        value,
                        verdict,
                        fetched_at,
                        result_json
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(indicator_type, value) DO UPDATE SET
                        verdict = excluded.verdict,
                        fetched_at = excluded.fetched_at,
                        result_json = excluded.result_json
                    """,
                    (
                        enrichment.indicator_type,
                        enrichment.value,
                        enrichment.verdict,
                        enrichment.fetched_at.isoformat(),
                        payload,
                    ),
                )

    def get_enrichment(
        self,
        indicator_type: str,
        value: str,
    ) -> IndicatorEnrichment | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT result_json
                FROM enrichments
                WHERE indicator_type = ? AND value = ?
                """,
                (indicator_type, value),
            ).fetchone()

        if row is None:
            return None

        return IndicatorEnrichment.model_validate_json(
            row["result_json"]
        )

    def list_enrichments(
        self,
        limit: int = 50,
    ) -> list[IndicatorEnrichment]:
        safe_limit = max(1, min(limit, 200))

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT result_json
                FROM enrichments
                ORDER BY fetched_at DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()

        return [
            IndicatorEnrichment.model_validate_json(
                row["result_json"]
            )
            for row in rows
        ]

    def save(
        self,
        result: TriageResult,
    ) -> None:
        """
        Salva o resultado completo como JSON e também
        mantém campos indexáveis para consultas rápidas.
        """
        payload = result.model_dump_json()

        verdict = (
            result.analysis.verdict
            if result.analysis
            else None
        )

        confidence = (
            result.analysis.confidence
            if result.analysis
            else None
        )

        completed_at = (
            result.completed_at.isoformat()
            if result.completed_at
            else None
        )

        parameters = (
            result.scan_id,
            result.requested_hash,
            result.hash_type,
            result.status,
            verdict,
            confidence,
            result.created_at.isoformat(),
            completed_at,
            payload,
        )

        with self._lock:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO scans (
                        scan_id,
                        requested_hash,
                        hash_type,
                        status,
                        verdict,
                        confidence,
                        created_at,
                        completed_at,
                        result_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        requested_hash = excluded.requested_hash,
                        hash_type = excluded.hash_type,
                        status = excluded.status,
                        verdict = excluded.verdict,
                        confidence = excluded.confidence,
                        created_at = excluded.created_at,
                        completed_at = excluded.completed_at,
                        result_json = excluded.result_json
                    """,
                    parameters,
                )

            self._append_csv(result)

    def _append_csv(
        self,
        result: TriageResult,
    ) -> None:
        """
        Mantém um histórico resumido em CSV.

        O SQLite continua sendo a fonte principal.
        """
        file_exists = (
            self.csv_path.exists()
            and self.csv_path.stat().st_size > 0
        )

        providers = ";".join(
            (
                f"{provider.provider}:"
                f"{provider.status}"
            )
            for provider in result.providers
        )

        row = {
            "scan_id": _safe_csv_cell(
                result.scan_id
            ),
            "requested_hash": _safe_csv_cell(
                result.requested_hash
            ),
            "hash_type": _safe_csv_cell(
                result.hash_type
            ),
            "status": _safe_csv_cell(
                result.status
            ),
            "verdict": _safe_csv_cell(
                result.analysis.verdict
                if result.analysis
                else ""
            ),
            "confidence": _safe_csv_cell(
                result.analysis.confidence
                if result.analysis
                else ""
            ),
            "created_at": _safe_csv_cell(
                result.created_at.isoformat()
            ),
            "completed_at": _safe_csv_cell(
                result.completed_at.isoformat()
                if result.completed_at
                else ""
            ),
            "providers": _safe_csv_cell(
                providers
            ),
            "observable_count": len(
                result.observables
            ),
        }

        with self.csv_path.open(
            "a",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=HISTORY_FIELDS,
            )

            if not file_exists:
                writer.writeheader()

            writer.writerow(row)

    def get(
        self,
        scan_id: str,
    ) -> TriageResult | None:
        """
        Busca uma análise pelo scan_id.
        """
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT result_json
                FROM scans
                WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchone()

        if row is None:
            return None

        return TriageResult.model_validate_json(
            row["result_json"]
        )

    def list(
        self,
        limit: int = 50,
        artifact_hash: str | None = None,
    ) -> list[TriageResult]:
        """
        Lista o histórico, opcionalmente filtrando por hash.
        """
        safe_limit = max(
            1,
            min(limit, 200),
        )

        query = """
            SELECT result_json
            FROM scans
        """

        parameters: list[object] = []

        if artifact_hash:
            query += """
                WHERE requested_hash = ?
            """

            parameters.append(
                artifact_hash.strip().lower()
            )

        query += """
            ORDER BY created_at DESC
            LIMIT ?
        """

        parameters.append(safe_limit)

        with self._connect() as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [
            TriageResult.model_validate_json(
                row["result_json"]
            )
            for row in rows
        ]

    def get_latest_for_hash(
        self,
        artifact_hash: str,
    ) -> TriageResult | None:
        """
        Retorna a análise mais recente para determinado hash.

        Esse método será utilizado futuramente pelo cache.
        """
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT result_json
                FROM scans
                WHERE requested_hash = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (
                    artifact_hash.strip().lower(),
                ),
            ).fetchone()

        if row is None:
            return None

        return TriageResult.model_validate_json(
            row["result_json"]
        )

    def search_observables(
        self,
        value: str,
        observable_type: ObservableType | None = None,
        exact: bool = False,
        limit: int = 100,
    ) -> list[ObservableOccurrence]:
        """Pesquisa observáveis nos resultados armazenados."""

        needle = value.strip().casefold()

        if not needle:
            return []

        safe_limit = max(1, min(limit, 500))

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT result_json
                FROM scans
                ORDER BY created_at DESC
                LIMIT 2000
                """
            ).fetchall()

        matches: list[ObservableOccurrence] = []

        for row in rows:
            result = TriageResult.model_validate_json(
                row["result_json"]
            )

            for observable in result.observables:
                if (
                    observable_type is not None
                    and observable.type != observable_type
                ):
                    continue

                candidate = observable.value.casefold()
                matched = (
                    candidate == needle
                    if exact
                    else needle in candidate
                )

                if not matched:
                    continue

                matches.append(
                    ObservableOccurrence(
                        scan_id=result.scan_id,
                        requested_hash=(
                            result.requested_hash
                        ),
                        created_at=result.created_at,
                        scan_status=result.status,
                        observable=observable,
                    )
                )

                if len(matches) >= safe_limit:
                    return matches

        return matches

    def get_stats(self) -> RepositoryStats:
        """Calcula indicadores resumidos do histórico."""

        with self._connect() as connection:
            totals = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_scans,
                    COUNT(DISTINCT requested_hash) AS unique_hashes
                FROM scans
                """
            ).fetchone()

            status_rows = connection.execute(
                """
                SELECT status, COUNT(*) AS quantity
                FROM scans
                GROUP BY status
                """
            ).fetchall()

            verdict_rows = connection.execute(
                """
                SELECT
                    COALESCE(verdict, 'unknown') AS verdict,
                    COUNT(*) AS quantity
                FROM scans
                GROUP BY COALESCE(verdict, 'unknown')
                """
            ).fetchall()

        return RepositoryStats(
            total_scans=(
                int(totals["total_scans"])
                if totals is not None
                else 0
            ),
            unique_hashes=(
                int(totals["unique_hashes"])
                if totals is not None
                else 0
            ),
            status_counts={
                str(row["status"]): int(row["quantity"])
                for row in status_rows
            },
            verdict_counts={
                str(row["verdict"]): int(row["quantity"])
                for row in verdict_rows
            },
        )

    def export_scan_csv(
        self,
        scan_id: str,
    ) -> str | None:
        """
        Gera um CSV detalhado para um scan específico.
        """
        result = self.get(scan_id)

        if result is None:
            return None

        buffer = io.StringIO(
            newline=""
        )

        writer = csv.writer(
            buffer,
            lineterminator="\n",
        )

        writer.writerow(
            [
                "category",
                "type",
                "value",
                "source",
                "relationship",
                "confidence",
            ]
        )

        for observable in result.observables:
            writer.writerow(
                [
                    "observable",
                    _safe_csv_cell(
                        observable.type
                    ),
                    _safe_csv_cell(
                        observable.value
                    ),
                    _safe_csv_cell(
                        observable.source
                    ),
                    _safe_csv_cell(
                        observable.relationship
                    ),
                    _safe_csv_cell(
                        observable.confidence
                    ),
                ]
            )

        if result.analysis:
            for candidate in (
                result.analysis.family_candidates
            ):
                writer.writerow(
                    [
                        "family",
                        "malware_family",
                        _safe_csv_cell(
                            candidate.family
                        ),
                        "analysis",
                        _safe_csv_cell(
                            ";".join(
                                candidate
                                .supporting_evidence_ids
                            )
                        ),
                        candidate.confidence,
                    ]
                )

            for ttp in result.analysis.ttps:
                writer.writerow(
                    [
                        "ttp",
                        _safe_csv_cell(
                            ttp.technique_id
                        ),
                        _safe_csv_cell(
                            ttp.technique_name
                        ),
                        "analysis",
                        _safe_csv_cell(
                            ";".join(
                                ttp.evidence_ids
                            )
                        ),
                        ttp.confidence,
                    ]
                )

        return buffer.getvalue()
