"""
Renderização do CTIReport em PDF (padrão técnico/executivo de CTI).

Estrutura:
- capa executiva: TLP, metadados, avaliação-chave, BLUF e julgamentos;
- corpo técnico: PIRs, artefato, família, ATT&CK, infraestrutura, IOCs
  (defanged), hunting, recomendações D3FEND, limitações e metodologia;
- anexos: escala de confiança, definição TLP e evidências.

Todo texto vindo de provedores externos é tratado como não confiável:
é escapado antes de entrar no mini-HTML do ReportLab (Paragraph) e
filtrado para os glifos disponíveis na fonte embutida.
"""

from __future__ import annotations

import io
import json
import os
import re

from contextvars import ContextVar
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Iterable
from xml.sax.saxutils import escape

import reportlab

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.models import CTIReport, Observable
from app.services.context_filters import is_known_infrastructure


PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN_X = 18 * mm
MARGIN_TOP = 24 * mm
MARGIN_BOTTOM = 20 * mm
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN_X
COVER_BAND_HEIGHT = 78 * mm

NAVY = colors.HexColor("#0B1F33")
NAVY_SOFT = colors.HexColor("#16324F")
ACCENT = colors.HexColor("#1FA38A")
TEXT = colors.HexColor("#1F2933")
MUTED = colors.HexColor("#5B6B7B")
RULE = colors.HexColor("#D9E2EC")
ZEBRA = colors.HexColor("#F4F7FA")
BLUF_BG = colors.HexColor("#EEF6F4")

VERDICT_COLORS = {
    "malicious": colors.HexColor("#C0392B"),
    "suspicious": colors.HexColor("#D68910"),
    "benign": colors.HexColor("#1E8449"),
    "unknown": MUTED,
}

CONFIDENCE_COLORS = {
    "high": colors.HexColor("#0B5394"),
    "medium": colors.HexColor("#D68910"),
    "low": MUTED,
}

# FIRST TLP 2.0: texto colorido sobre fundo preto.
TLP_COLORS = {
    "TLP:CLEAR": colors.HexColor("#FFFFFF"),
    "TLP:GREEN": colors.HexColor("#33FF00"),
    "TLP:AMBER": colors.HexColor("#FFC000"),
    "TLP:RED": colors.HexColor("#FF2B2B"),
}

TLP_DEFINITIONS = {
    "TLP:CLEAR": "Divulgação sem restrição, sujeita às regras de direitos autorais.",
    "TLP:GREEN": "Divulgação limitada à comunidade do destinatário; não publicar.",
    "TLP:AMBER": "Divulgação limitada à organização do destinatário e clientes que precisem saber.",
    "TLP:RED": "Somente para os participantes nomeados; não redistribuir.",
}

VERDICT_LABELS = {
    "malicious": "Malicioso",
    "suspicious": "Suspeito",
    "benign": "Benigno",
    "unknown": "Indeterminado",
}

CONFIDENCE_LABELS = {
    "high": "Alta",
    "medium": "Moderada",
    "low": "Baixa",
}

PIR_STATUS_LABELS = {
    "answered": "Respondido",
    "partially_answered": "Parcial",
    "unanswered": "Sem resposta",
}

INFRA_LABELS = {
    "known_infrastructure": "Infra. conhecida (SO/CDN)",
    "related_infrastructure": "Relacionada",
    "observed_network_activity": "Atividade observada",
    "candidate_c2": "Candidato a C2",
    "confirmed_c2": "C2 confirmado",
}

PHASE_LABELS = {
    "containment": "Contenção",
    "eradication": "Erradicação",
    "recovery": "Recuperação",
    "hardening": "Hardening",
    "detection": "Detecção",
}

ENGINE_LABELS = {
    "genai": "GenAI + grounding",
    "deterministic": "Determinístico",
    "deterministic_fallback": "Determinístico (fallback)",
}

MAX_CELL_CHARS = 700
MAX_EVIDENCE_CHARS = 220

FONT_DIRECTORY = os.path.join(
    os.path.dirname(reportlab.__file__),
    "fonts",
)

FALLBACK_CHARACTERS = {
    "→": "->",
    "←": "<-",
    "≥": ">=",
    "≤": "<=",
    "≠": "!=",
    "…": "...",
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
    " ": " ",
}

CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# Pares (valor, valor defanged) dos IOCs de rede do relatório em renderização.
# Aplicados a todo texto livre para que nenhum IOC saia "vivo" no PDF.
_DEFANG_PAIRS: ContextVar[tuple[tuple[str, str], ...]] = ContextVar(
    "defang_pairs",
    default=(),
)


@lru_cache(maxsize=1)
def _register_fonts() -> frozenset[int]:
    """
    Registra a Bitstream Vera distribuída com o ReportLab (embutida no PDF)
    e retorna os codepoints suportados.
    """
    faces = {
        "CTI": "Vera.ttf",
        "CTI-Bold": "VeraBd.ttf",
        "CTI-Italic": "VeraIt.ttf",
        "CTI-BoldItalic": "VeraBI.ttf",
    }

    supported: set[int] = set()

    for name, filename in faces.items():
        font = TTFont(name, os.path.join(FONT_DIRECTORY, filename))
        pdfmetrics.registerFont(font)

        if name == "CTI":
            supported = set(font.face.charToGlyph)

    pdfmetrics.registerFontFamily(
        "CTI",
        normal="CTI",
        bold="CTI-Bold",
        italic="CTI-Italic",
        boldItalic="CTI-BoldItalic",
    )

    return frozenset(supported)


def _clean(
    value: Any,
    limit: int | None = None,
    defang_iocs: bool = True,
) -> str:
    """Normaliza texto externo para a fonte embutida (sem markup)."""

    if value is None:
        return ""

    text = CONTROL_CHARACTERS.sub(" ", str(value))

    if defang_iocs:
        for live, defanged in _DEFANG_PAIRS.get():
            text = text.replace(live, defanged)

    for source, target in FALLBACK_CHARACTERS.items():
        text = text.replace(source, target)

    supported = _register_fonts()
    text = "".join(
        character
        if ord(character) in supported or character in "\n\t"
        else "?"
        for character in text
    )

    if limit is not None and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"

    return text


def _safe(value: Any, limit: int | None = MAX_CELL_CHARS) -> str:
    """Texto externo pronto para Paragraph: limpo e escapado."""

    return escape(_clean(value, limit)).replace("\n", "<br/>")


def _mono(value: Any, limit: int | None = MAX_CELL_CHARS) -> str:
    """Courier é WinAnsi: restringe a cp1252 e quebra hashes longos."""

    text = _clean(value, limit).encode("cp1252", "replace").decode("cp1252")
    # Paragraph quebra palavras longas (splitLongWords) sem markup extra.
    return escape(text)


def _code(value: str) -> str:
    """
    Bloco de código de regra: sem defang (precisa funcionar ao ser copiado),
    com quebras de linha e indentação preservadas.
    """

    text = _clean(value, 6000, defang_iocs=False)
    text = text.encode("cp1252", "replace").decode("cp1252")

    lines = []
    for line in escape(text).split("\n"):
        stripped = line.lstrip(" ")
        lines.append("&nbsp;" * (len(line) - len(stripped)) + stripped)

    return "<br/>".join(lines)


def defang(observable_type: str, value: str) -> str:
    """Formato defanged padrão para IOCs de rede em relatórios."""

    if observable_type == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
        return value.replace("://", "[://]").replace(".", "[.]")

    if observable_type in {"ip", "domain"}:
        return value.replace(".", "[.]")

    return value


def _styles() -> dict[str, ParagraphStyle]:
    _register_fonts()

    base = ParagraphStyle(
        "base",
        fontName="CTI",
        fontSize=9,
        leading=12.5,
        textColor=TEXT,
        alignment=TA_LEFT,
    )

    return {
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.8, leading=10.2),
        "muted": ParagraphStyle("muted", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.8, leading=10),
        "cell_mono": ParagraphStyle(
            "cell_mono", parent=base, fontName="Courier", fontSize=7.2, leading=9.2
        ),
        "code": ParagraphStyle(
            "code", parent=base, fontName="Courier", fontSize=7, leading=9,
            textColor=colors.HexColor("#0F2A3F"),
        ),
        "rule_title": ParagraphStyle(
            "rule_title", parent=base, fontName="CTI-Bold", fontSize=9, leading=12,
            textColor=NAVY,
        ),
        "cell_head": ParagraphStyle(
            "cell_head", parent=base, fontName="CTI-Bold", fontSize=7.4, leading=9.5,
            textColor=colors.white,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base, fontName="CTI-Bold", fontSize=13.5, leading=17,
            textColor=NAVY, spaceBefore=4, spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base, fontName="CTI-Bold", fontSize=10.5, leading=14,
            textColor=NAVY_SOFT, spaceBefore=8, spaceAfter=4,
        ),
        "eyebrow": ParagraphStyle(
            "eyebrow", parent=base, fontName="CTI-Bold", fontSize=7.2, leading=9,
            textColor=ACCENT,
        ),
        "kpi_label": ParagraphStyle(
            "kpi_label", parent=base, fontName="CTI-Bold", fontSize=6.8, leading=8.5,
            textColor=MUTED,
        ),
        "kpi_value": ParagraphStyle(
            "kpi_value", parent=base, fontName="CTI-Bold", fontSize=12, leading=15,
            textColor=NAVY,
        ),
        "bluf": ParagraphStyle("bluf", parent=base, fontSize=9.4, leading=13.6),
        "bullet": ParagraphStyle(
            "bullet", parent=base, leftIndent=10, bulletIndent=0, spaceAfter=2.5,
        ),
    }


def _table(
    headers: list[str],
    rows: list[list[Any]],
    widths: list[float],
    styles: dict[str, ParagraphStyle],
    mono_columns: Iterable[int] = (),
) -> Table:
    """Tabela técnica com cabeçalho repetido e zebra."""

    mono = set(mono_columns)

    data: list[list[Any]] = [
        [Paragraph(escape(header), styles["cell_head"]) for header in headers]
    ]

    for row in rows:
        data.append(
            [
                cell
                if not isinstance(cell, str)
                else Paragraph(cell, styles["cell_mono" if index in mono else "cell"])
                for index, cell in enumerate(row)
            ]
        )

    table = Table(
        data,
        colWidths=[width * CONTENT_WIDTH for width in widths],
        repeatRows=1,
    )

    commands: list[tuple[Any, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]

    for index in range(1, len(data)):
        if index % 2 == 0:
            commands.append(("BACKGROUND", (0, index), (-1, index), ZEBRA))

    table.setStyle(TableStyle(commands))
    return table


def _hex(color: colors.Color) -> str:
    red, green, blue = (round(channel * 255) for channel in color.rgb())
    return f"#{red:02x}{green:02x}{blue:02x}"


def _colored(label: str, color: colors.Color, bold: bool = True) -> str:
    font = "CTI-Bold" if bold else "CTI"
    return f'<font name="{font}" color="{_hex(color)}">{escape(label)}</font>'


def _confidence(value: str) -> str:
    return _colored(
        CONFIDENCE_LABELS.get(value, value),
        CONFIDENCE_COLORS.get(value, MUTED),
    )


def _bullets(items: Iterable[str], styles: dict[str, ParagraphStyle]) -> list[Paragraph]:
    return [
        Paragraph(_safe(item), styles["bullet"], bulletText="•")
        for item in items
        if item
    ]


def _empty(message: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(escape(message), styles["muted"])


def _section(number: str, title: str, styles: dict[str, ParagraphStyle]) -> list[Any]:
    return [
        Paragraph(f"{escape(number)}&nbsp;&nbsp;{escape(title)}", styles["h1"]),
    ]


def _format_datetime(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    return _clean(value) or "—"


# ---------------------------------------------------------------------------
# Decoração de página
# ---------------------------------------------------------------------------


def _draw_tlp_badge(canvas: pdf_canvas.Canvas, tlp: str, right: float, top: float, size: float = 8) -> None:
    canvas.saveState()
    canvas.setFont("CTI-Bold", size)
    text_width = pdfmetrics.stringWidth(tlp, "CTI-Bold", size)
    width = text_width + 10
    height = size + 7
    canvas.setFillColor(colors.black)
    canvas.roundRect(right - width, top - height, width, height, 2.5, stroke=0, fill=1)
    canvas.setFillColor(TLP_COLORS.get(tlp, colors.white))
    canvas.drawString(right - width + 5, top - height + 4.2, tlp)
    canvas.restoreState()


def _canvas_factory(report: CTIReport):
    """Canvas com 'Página X de Y' e marcação TLP em todas as páginas."""

    tlp = report.classification

    class NumberedCanvas(pdf_canvas.Canvas):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._saved_pages: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 (API do ReportLab)
            self._saved_pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._saved_pages)

            for state in self._saved_pages:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()

            super().save()

        def _decorate(self, total: int) -> None:
            page = self._pageNumber
            self.saveState()

            if page > 1:
                # Cabeçalho
                top = PAGE_HEIGHT - 12 * mm
                self.setFont("CTI-Bold", 7)
                self.setFillColor(NAVY)
                label = "CYBER THREAT INTELLIGENCE"
                self.drawString(MARGIN_X, top - 7, label)
                offset = pdfmetrics.stringWidth(label, "CTI-Bold", 7) + 10
                self.setFont("CTI", 7)
                self.setFillColor(MUTED)
                self.drawString(
                    MARGIN_X + offset,
                    top - 7,
                    f"Relatório de triagem · {report.artifact.requested_hash[:16]}…",
                )
                _draw_tlp_badge(self, tlp, PAGE_WIDTH - MARGIN_X, top + 1, 7)
                self.setStrokeColor(ACCENT)
                self.setLineWidth(1.2)
                self.line(MARGIN_X, top - 12, PAGE_WIDTH - MARGIN_X, top - 12)

            # Rodapé (inclusive na capa)
            bottom = 11 * mm
            self.setStrokeColor(RULE)
            self.setLineWidth(0.5)
            self.line(MARGIN_X, bottom + 9, PAGE_WIDTH - MARGIN_X, bottom + 9)
            self.setFont("CTI", 6.8)
            self.setFillColor(MUTED)
            self.drawString(MARGIN_X, bottom, f"{report.report_id}")
            self.drawCentredString(
                PAGE_WIDTH / 2,
                bottom,
                f"{tlp} · Gerado em {_format_datetime(report.generated_at)}",
            )
            self.drawRightString(
                PAGE_WIDTH - MARGIN_X,
                bottom,
                f"Página {page} de {total}",
            )
            self.restoreState()

    return NumberedCanvas


def _draw_cover_band(report: CTIReport):
    def draw(canvas: pdf_canvas.Canvas, _doc: Any) -> None:
        canvas.saveState()
        band_bottom = PAGE_HEIGHT - COVER_BAND_HEIGHT
        canvas.setFillColor(NAVY)
        canvas.rect(0, band_bottom, PAGE_WIDTH, COVER_BAND_HEIGHT, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, band_bottom, PAGE_WIDTH, 2.2, stroke=0, fill=1)

        top = PAGE_HEIGHT - 20 * mm
        canvas.setFillColor(ACCENT)
        canvas.setFont("CTI-Bold", 8)
        canvas.drawString(MARGIN_X, top, "CYBER THREAT INTELLIGENCE  ·  MALWARE TRIAGE")

        canvas.setFillColor(colors.white)
        canvas.setFont("CTI-Bold", 22)
        canvas.drawString(MARGIN_X, top - 30, "Relatório de Inteligência")
        canvas.drawString(MARGIN_X, top - 57, "de Ameaças")

        canvas.setFont("Courier", 8.6)
        canvas.setFillColor(colors.HexColor("#B8C7D6"))
        canvas.drawString(MARGIN_X, top - 82, f"SHA-256  {report.artifact.hashes.get('sha256', report.artifact.requested_hash)}")

        canvas.setFont("CTI", 8)
        canvas.drawString(
            MARGIN_X,
            top - 97,
            f"{report.report_id}   ·   {_format_datetime(report.generated_at)}",
        )

        _draw_tlp_badge(canvas, report.classification, PAGE_WIDTH - MARGIN_X, PAGE_HEIGHT - 16 * mm, 9)
        canvas.restoreState()

    return draw


# ---------------------------------------------------------------------------
# Conteúdo
# ---------------------------------------------------------------------------


def _kpi_tiles(report: CTIReport, styles: dict[str, ParagraphStyle]) -> Table:
    family = (
        report.family_candidates[0].family
        if report.family_candidates
        else "Não atribuída"
    )
    c2_candidates = sum(
        1 for item in report.infrastructure if item.classification == "candidate_c2"
    )
    confirmed = sum(
        1 for item in report.infrastructure if item.classification == "confirmed_c2"
    )

    tiles = [
        ("VEREDITO", VERDICT_LABELS.get(report.verdict, report.verdict), VERDICT_COLORS.get(report.verdict, MUTED)),
        ("CONFIANÇA", CONFIDENCE_LABELS.get(report.confidence, report.confidence), CONFIDENCE_COLORS.get(report.confidence, MUTED)),
        ("FAMÍLIA (HIPÓTESE)", _clean(family, 28), NAVY),
        ("TTPs SUSTENTADAS", str(len(report.ttps)), NAVY),
        ("C2", f"{confirmed} conf. / {c2_candidates} cand.", NAVY),
    ]

    cells = []
    for label, value, color in tiles:
        value_style = ParagraphStyle("kv", parent=styles["kpi_value"], textColor=color)
        if len(value) > 10:
            value_style.fontSize = 9.5
            value_style.leading = 12
        cells.append([
            Paragraph(escape(label), styles["kpi_label"]),
            Spacer(1, 2),
            Paragraph(escape(value), value_style),
        ])

    table = Table([cells], colWidths=[CONTENT_WIDTH / len(tiles)] * len(tiles))
    commands: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), ZEBRA),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("LINEAFTER", (0, 0), (-2, -1), 3, colors.white),
    ]
    for index, (_label, _value, color) in enumerate(tiles):
        commands.append(("LINEABOVE", (index, 0), (index, 0), 2.4, color))
    table.setStyle(TableStyle(commands))
    return table


def _metadata_table(report: CTIReport, styles: dict[str, ParagraphStyle]) -> Table:
    execution = report.analysis_execution
    providers = ", ".join(
        f"{item.provider} ({item.status})" for item in report.providers
    ) or "—"
    model = execution.model or "—"
    if execution.provider:
        model = f"{execution.provider} / {model}"

    pairs = [
        ("Report ID", _mono(report.report_id)),
        ("Scan ID", _mono(report.scan_id)),
        ("Status da coleta", _safe(report.status)),
        ("Fontes", _safe(providers)),
        ("Motor analítico", _safe(ENGINE_LABELS.get(execution.engine, execution.engine))),
        ("Modelo", _safe(model)),
        ("TLP", _safe(report.classification)),
        ("Gerado em", _safe(_format_datetime(report.generated_at))),
    ]

    rows = []
    for index in range(0, len(pairs), 2):
        row = []
        for label, value in pairs[index:index + 2]:
            row.extend([
                Paragraph(escape(label.upper()), styles["kpi_label"]),
                Paragraph(value, styles["cell_mono" if label.endswith("ID") else "cell"]),
            ])
        rows.append(row)

    table = Table(
        rows,
        colWidths=[
            CONTENT_WIDTH * 0.13,
            CONTENT_WIDTH * 0.39,
            CONTENT_WIDTH * 0.12,
            CONTENT_WIDTH * 0.36,
        ],
    )
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]))
    return table


def _bluf_box(report: CTIReport, styles: dict[str, ParagraphStyle]) -> Table:
    content = [
        Paragraph("BOTTOM LINE UP FRONT", styles["eyebrow"]),
        Spacer(1, 3),
        Paragraph(_safe(report.executive_summary, 1600), styles["bluf"]),
    ]
    table = Table([[content]], colWidths=[CONTENT_WIDTH])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLUF_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 3, ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return table


def _key_judgments(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    flowables: list[Any] = [Paragraph("Julgamentos-chave", styles["h2"])]

    if not report.intelligence_requirements:
        flowables.append(_empty("Nenhum requisito de inteligência avaliado.", styles))
        return flowables

    for index, pir in enumerate(report.intelligence_requirements, start=1):
        flowables.append(
            Paragraph(
                f'<font name="CTI-Bold" color="{_hex(NAVY)}">KJ{index}.</font> '
                f"{_safe(pir.assessment, 400)} "
                f'<font color="{_hex(MUTED)}">— confiança</font> {_confidence(pir.confidence)}',
                styles["bullet"],
            )
        )

    return flowables


def _priority_actions(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    urgent = [item for item in report.recommendations if item.priority == "P0"][:4]

    if not urgent:
        return []

    flowables: list[Any] = [Paragraph("Ações prioritárias (P0)", styles["h2"])]

    for item in urgent:
        d3fend = f' <font color="{_hex(MUTED)}">[{escape(item.d3fend_id)}]</font>' if item.d3fend_id else ""
        flowables.append(
            Paragraph(
                f'<font name="CTI-Bold" color="{_hex(ACCENT)}">'
                f"{escape(PHASE_LABELS.get(item.phase, item.phase))}</font> — "
                f"{_safe(item.action, 260)}{d3fend}",
                styles["bullet"],
                bulletText="»",
            )
        )

    return flowables


def _cover(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    return [
        _metadata_table(report, styles),
        Spacer(1, 9),
        _kpi_tiles(report, styles),
        Spacer(1, 10),
        _bluf_box(report, styles),
        Spacer(1, 4),
        *_key_judgments(report, styles),
        *_priority_actions(report, styles),
        Spacer(1, 8),
        Paragraph(
            f"<b>{escape(report.classification)}</b> — "
            f"{escape(TLP_DEFINITIONS.get(report.classification, ''))} "
            "Conteúdo derivado de fontes abertas e de análise automatizada com "
            "grounding em evidências; valide antes de ações de bloqueio permanente.",
            styles["muted"],
        ),
    ]


def _pir_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("1", "Requisitos de inteligência (PIRs)", styles)
    rows = [
        [
            _mono(pir.pir_id),
            _safe(pir.question),
            _safe(PIR_STATUS_LABELS.get(pir.status, pir.status)),
            _confidence(pir.confidence),
            _safe(pir.assessment),
        ]
        for pir in report.intelligence_requirements
    ]
    story.append(
        _table(
            ["PIR", "Pergunta", "Status", "Confiança", "Avaliação"],
            rows,
            [0.08, 0.25, 0.13, 0.12, 0.42],
            styles,
            mono_columns=[0],
        )
        if rows
        else _empty("Sem PIRs.", styles)
    )
    return story


def _artifact_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    artifact = report.artifact
    story = _section("2", "Perfil do artefato e fontes", styles)

    rows = [
        ["MD5", _mono(artifact.hashes.get("md5", "—"))],
        ["SHA-1", _mono(artifact.hashes.get("sha1", "—"))],
        ["SHA-256", _mono(artifact.hashes.get("sha256", artifact.requested_hash))],
        ["Tipo", _safe(", ".join(artifact.file_types) or "—")],
        ["Tamanho", _safe(", ".join(f"{size:,} bytes".replace(",", ".") for size in artifact.file_sizes) or "—")],
        ["Nomes observados", _safe(", ".join(artifact.filenames[:12]) or "—")],
        ["Tags", _safe(", ".join(artifact.tags[:20]) or "—")],
        ["Primeira observação", _safe(artifact.first_seen or "—")],
        ["Última observação", _safe(artifact.last_seen or "—")],
    ]
    story.append(
        _table(
            ["Atributo", "Valor"],
            [[escape(label), value] for label, value in rows],
            [0.22, 0.78],
            styles,
        )
    )

    story.append(Paragraph("Fontes consultadas", styles["h2"]))
    provider_rows = [
        [
            _safe(item.provider),
            _safe(item.status),
            _safe(_format_datetime(item.fetched_at)),
            _safe(item.error or "—"),
        ]
        for item in report.providers
    ]
    story.append(
        _table(
            ["Fonte", "Status", "Coleta", "Erro"],
            provider_rows,
            [0.2, 0.14, 0.24, 0.42],
            styles,
        )
        if provider_rows
        else _empty("Nenhuma fonte registrada.", styles)
    )
    return story


def _family_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("3", "Atribuição de família", styles)
    story.append(
        Paragraph(
            "Hipóteses ordenadas por confiança. Rótulos de fornecedores são indicativos; "
            "sinais de artefatos da cadeia (pai/dropados) corroboram o ecossistema, "
            "não a identidade da amostra.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4))
    rows = [
        [
            _safe(candidate.family),
            _confidence(candidate.confidence),
            _mono(", ".join(candidate.supporting_evidence_ids) or "—"),
            _mono(", ".join(candidate.contradicting_evidence_ids) or "—"),
            _safe(candidate.rationale),
        ]
        for candidate in report.family_candidates
    ]
    story.append(
        _table(
            ["Família", "Confiança", "Evidências", "Contrárias", "Racional"],
            rows,
            [0.15, 0.12, 0.13, 0.12, 0.48],
            styles,
            mono_columns=[2, 3],
        )
        if rows
        else _empty("Nenhuma família sustentada após o grounding.", styles)
    )
    return story


def _ttp_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("4", "Comportamento — MITRE ATT&CK", styles)
    rows = [
        [
            _mono(ttp.technique_id),
            _safe(ttp.technique_name),
            _confidence(ttp.confidence),
            _mono(", ".join(ttp.evidence_ids)),
            _safe(ttp.rationale),
        ]
        for ttp in report.ttps
    ]
    story.append(
        _table(
            ["Técnica", "Nome", "Confiança", "Evidências", "Racional"],
            rows,
            [0.1, 0.22, 0.12, 0.16, 0.4],
            styles,
            mono_columns=[0, 3],
        )
        if rows
        else _empty(
            "Nenhuma técnica sustentada por evidência comportamental da plataforma do artefato.",
            styles,
        )
    )
    return story


def _infrastructure_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("5", "Infraestrutura e avaliação de C2", styles)

    known = [
        item for item in report.infrastructure
        if item.classification == "known_infrastructure"
    ]
    actionable = [
        item for item in report.infrastructure
        if item.classification != "known_infrastructure"
    ]

    order = ["confirmed_c2", "candidate_c2", "observed_network_activity", "related_infrastructure"]
    actionable.sort(key=lambda item: order.index(item.classification))

    counts = {}
    for item in report.infrastructure:
        counts[item.classification] = counts.get(item.classification, 0) + 1

    story.append(
        Paragraph(
            " · ".join(
                f"<b>{escape(INFRA_LABELS[key])}</b>: {counts[key]}"
                for key in INFRA_LABELS
                if key in counts
            )
            or "Nenhum observável de rede.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 5))

    rows = [
        [
            _mono(defang(item.observable.type, item.observable.value)),
            _safe(item.observable.type),
            _safe(INFRA_LABELS.get(item.classification, item.classification)),
            _safe(item.observable.relationship or "—"),
            _safe(item.rationale, 300),
        ]
        for item in actionable
    ]
    if rows:
        story.append(
            _table(
                ["Indicador", "Tipo", "Classificação", "Relação", "Racional"],
                rows,
                [0.24, 0.07, 0.15, 0.14, 0.4],
                styles,
                mono_columns=[0],
            )
        )

    if known:
        story.append(Spacer(1, 6))
        owners = sorted({
            str(item.observable.context.get("known_infrastructure") or "SO/CDN")
            for item in known
        })
        story.append(
            Paragraph(
                f"<b>Não bloquear — infraestrutura conhecida ({escape(', '.join(owners))}):</b> "
                + _mono(", ".join(defang(item.observable.type, item.observable.value) for item in known), 900),
                styles["small"],
            )
        )

    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "Nenhum indicador é promovido automaticamente a C2 confirmado; exige corroboração "
            "temporal, comportamental e contextual.",
            styles["muted"],
        )
    )
    return story


def _ioc_rows(report: CTIReport) -> list[list[str]]:
    rows: list[list[str]] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: str, value: str, context: str) -> None:
        key = (ioc_type, value.casefold())
        if key in seen:
            return
        seen.add(key)
        rows.append([_safe(ioc_type), _mono(defang(ioc_type, value)), _safe(context, 160)])

    for algorithm in ("sha256", "sha1", "md5"):
        value = report.artifact.hashes.get(algorithm)
        if value:
            add(algorithm, value, "Amostra analisada")

    observables: list[Observable] = report.observables
    for observable in observables:
        if observable.type == "hash":
            add("sha256", observable.value, observable.relationship or "Relacionado")

    for observable in observables:
        if observable.type in {"ip", "domain", "url"} and not is_known_infrastructure(observable):
            add(observable.type, observable.value, observable.relationship or "Relacionado")

    return rows


def _ioc_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("6", "Indicadores de comprometimento (IOCs)", styles)
    story.append(
        Paragraph(
            "Indicadores de rede em formato defanged. Infraestrutura de SO/CDN foi excluída "
            "desta lista. Revalide antes de bloqueio permanente.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4))
    rows = _ioc_rows(report)
    story.append(
        _table(["Tipo", "Indicador", "Contexto"], rows, [0.1, 0.62, 0.28], styles, mono_columns=[1])
        if rows
        else _empty("Nenhum IOC acionável.", styles)
    )
    return story


def _hunting_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("7", "Threat hunting", styles)

    if report.hunting_hypotheses:
        story.append(Paragraph("Hipóteses de caça", styles["h2"]))
        story.extend(_bullets(report.hunting_hypotheses, styles))

    rows = [
        [
            _safe(item.priority),
            _safe(item.data_source),
            _safe(item.objective),
            _safe(item.procedure),
            _safe("; ".join(item.expected_evidence), 400),
        ]
        for item in report.hunting_checklist
    ]
    if rows:
        story.append(Paragraph("Checklist de investigação", styles["h2"]))
        story.append(
            _table(
                ["Prio.", "Fonte de dados", "Objetivo", "Procedimento", "Evidência esperada"],
                rows,
                [0.07, 0.17, 0.22, 0.28, 0.26],
                styles,
            )
        )
    return story


LANGUAGE_LABELS = {
    "yara": "YARA",
    "sigma": "SIGMA",
    "kql": "KQL",
    "eql": "EQL",
}


def _detection_rules_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("8", "Regras de detecção", styles)
    story.append(
        Paragraph(
            "Geradas automaticamente a partir dos IOCs e dos comportamentos observados "
            "neste scan. O conteúdo das regras não é defanged, para funcionar ao ser "
            "copiado. Valide em ambiente de teste antes de publicar em produção.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 6))

    if not report.detection_rules:
        story.append(_empty("Não há IOCs ou comportamentos suficientes para gerar regras.", styles))
        return story

    for rule in report.detection_rules:
        basis = "Baseada em IOC" if rule.basis == "ioc" else "Baseada em comportamento"
        meta = [escape(rule.platform), basis]
        if rule.mitre_attack:
            meta.append("ATT&amp;CK " + escape(", ".join(rule.mitre_attack)))
        if rule.evidence_ids:
            meta.append("Evidências " + escape(", ".join(rule.evidence_ids)))

        header = Paragraph(
            f"{escape(rule.rule_id)}&nbsp;&nbsp;·&nbsp;&nbsp;{_safe(rule.title)}&nbsp;&nbsp;"
            + _colored(LANGUAGE_LABELS.get(rule.language, rule.language), ACCENT),
            styles["rule_title"],
        )
        code = Table(
            [[Paragraph(_code(rule.content), styles["code"])]],
            colWidths=[CONTENT_WIDTH],
        )
        code.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ZEBRA),
            ("LINEBEFORE", (0, 0), (0, -1), 2.2, ACCENT),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        story.append(
            KeepTogether([
                header,
                Paragraph(" · ".join(meta), styles["muted"]),
                Spacer(1, 2),
                Paragraph(f"<b>Hipótese:</b> {_safe(rule.hypothesis)}", styles["small"]),
                Paragraph(_safe(rule.rationale), styles["muted"]),
                Spacer(1, 3),
                code,
                Spacer(1, 10),
            ])
        )

    return story


def _recommendation_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("9", "Recomendações e MITRE D3FEND", styles)
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    recommendations = sorted(
        report.recommendations,
        key=lambda item: priority_order.get(item.priority, 9),
    )
    rows = [
        [
            _colored(item.priority, VERDICT_COLORS["malicious"] if item.priority == "P0" else NAVY),
            _safe(PHASE_LABELS.get(item.phase, item.phase)),
            _safe(item.action),
            _mono(item.d3fend_id or "—"),
            _safe(item.validation),
        ]
        for item in recommendations
    ]
    story.append(
        _table(
            ["Prio.", "Fase", "Ação", "D3FEND", "Validação"],
            rows,
            [0.07, 0.14, 0.39, 0.1, 0.3],
            styles,
            mono_columns=[3],
        )
        if rows
        else _empty("Nenhuma recomendação registrada.", styles)
    )
    return story


def _limitations_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("10", "Limitações, lacunas e caveats", styles)
    story.extend(_bullets(report.limitations, styles) or [_empty("Nenhuma.", styles)])
    return story


def _methodology_section(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    execution = report.analysis_execution
    story = _section("11", "Metodologia e execução da análise", styles)
    story.extend(_bullets(report.methodology, styles))
    story.append(Spacer(1, 4))
    rows = [
        ["Motor", _safe(ENGINE_LABELS.get(execution.engine, execution.engine))],
        ["GenAI solicitada / executada", _safe(f"{'sim' if execution.requested else 'não'} / {'sim' if execution.succeeded else 'não'}")],
        ["Provedor / modelo", _safe(f"{execution.provider or '—'} / {execution.model or '—'}")],
        ["Fallback", _safe(f"{'sim' if execution.fallback_used else 'não'}{f' ({execution.error_code})' if execution.error_code else ''}")],
        ["Tokens (entrada / saída / total)", _safe(f"{execution.usage.input_tokens} / {execution.usage.output_tokens} / {execution.usage.total_tokens}")],
    ]
    story.append(_table(["Parâmetro", "Valor"], [[escape(a), b] for a, b in rows], [0.35, 0.65], styles))
    return story


def _annex_scales(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("A", "Anexo — escalas e marcações", styles)
    story.append(Paragraph("Níveis de confiança", styles["h2"]))
    story.append(
        _table(
            ["Nível", "Significado"],
            [
                [_confidence("high"), _safe("Múltiplas fontes independentes e/ou evidência comportamental direta; julgamento improvável de mudar.")],
                [_confidence("medium"), _safe("Fonte única confiável ou corroboração parcial; plausível, com lacunas relevantes.")],
                [_confidence("low"), _safe("Fonte única, sinal indireto ou fragmentado; tratar como hipótese.")],
            ],
            [0.15, 0.85],
            styles,
        )
    )
    story.append(Paragraph("Traffic Light Protocol (FIRST TLP 2.0)", styles["h2"]))
    story.append(
        _table(
            ["Marcação", "Compartilhamento"],
            [[_safe(key), _safe(value)] for key, value in TLP_DEFINITIONS.items()],
            [0.15, 0.85],
            styles,
        )
    )
    return story


def _evidence_text(kind: str, value: Any) -> str:
    # Observáveis de rede também são defanged no anexo.
    if (
        kind.startswith("observable_")
        and isinstance(value, dict)
        and isinstance(value.get("value"), str)
    ):
        value = {
            **value,
            "value": defang(str(value.get("type", "")), value["value"]),
        }

    if isinstance(value, str):
        return value

    return json.dumps(value, ensure_ascii=False, default=str)


def _annex_evidence(report: CTIReport, styles: dict[str, ParagraphStyle]) -> list[Any]:
    story = _section("B", "Anexo — evidências", styles)
    story.append(
        Paragraph(
            "Valores truncados. O registro completo está disponível em "
            f"GET /api/v1/scans/{escape(report.scan_id)}.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4))
    rows = [
        [
            _mono(item.id),
            _safe(item.source),
            _safe(item.kind.replace("_", " ")),
            _mono(_evidence_text(item.kind, item.value), MAX_EVIDENCE_CHARS),
        ]
        for item in report.evidence
    ]
    story.append(
        _table(["ID", "Fonte", "Tipo", "Valor"], rows, [0.07, 0.12, 0.23, 0.58], styles, mono_columns=[0, 3])
        if rows
        else _empty("Sem evidências.", styles)
    )
    return story


def render_cti_report_pdf(report: CTIReport) -> bytes:
    """Gera o PDF do relatório CTI e retorna os bytes."""

    styles = _styles()
    buffer = io.BytesIO()

    pairs = {
        observable.value: defang(observable.type, observable.value)
        for observable in report.observables
        if observable.type in {"ip", "domain", "url"} and observable.value
    }
    # Mais longos primeiro: URLs antes dos domínios que as compõem.
    token = _DEFANG_PAIRS.set(
        tuple(sorted(pairs.items(), key=lambda item: -len(item[0])))
    )

    document = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
        title=_clean(report.title),
        author="CTI Triage",
        subject=f"{report.classification} · Relatório de triagem de malware",
        keywords="CTI, malware, MITRE ATT&CK, D3FEND, IOC",
        creator="CTI Triage",
    )

    cover_frame = Frame(
        MARGIN_X,
        MARGIN_BOTTOM,
        CONTENT_WIDTH,
        PAGE_HEIGHT - COVER_BAND_HEIGHT - MARGIN_BOTTOM - 7 * mm,
        id="cover",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    body_frame = Frame(
        MARGIN_X,
        MARGIN_BOTTOM,
        CONTENT_WIDTH,
        PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM,
        id="body",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )

    document.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_draw_cover_band(report)),
        PageTemplate(id="body", frames=[body_frame]),
    ])

    def block(flowables: list[Any]) -> list[Any]:
        # Mantém o título da seção junto do primeiro elemento.
        if len(flowables) >= 2:
            return [KeepTogether(flowables[:2]), *flowables[2:], Spacer(1, 10)]
        return [*flowables, Spacer(1, 10)]

    story: list[Any] = [
        # Qualquer página após a capa (inclusive transbordo) usa o corpo.
        NextPageTemplate("body"),
        *_cover(report, styles),
        PageBreak(),
    ]

    for builder in (
        _pir_section,
        _artifact_section,
        _family_section,
        _ttp_section,
        _infrastructure_section,
        _ioc_section,
        _hunting_section,
        _detection_rules_section,
        _recommendation_section,
        _limitations_section,
        _methodology_section,
    ):
        story.extend(block(builder(report, styles)))

    story.append(PageBreak())
    story.extend(block(_annex_scales(report, styles)))
    story.extend(block(_annex_evidence(report, styles)))

    try:
        document.build(story, canvasmaker=_canvas_factory(report))
    finally:
        _DEFANG_PAIRS.reset(token)

    return buffer.getvalue()
