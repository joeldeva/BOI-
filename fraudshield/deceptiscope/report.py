from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


NAVY = colors.HexColor("#0B1930")
BLUE = colors.HexColor("#1677FF")
RED = colors.HexColor("#C62828")
AMBER = colors.HexColor("#B26A00")
GREEN = colors.HexColor("#18794E")
SLATE = colors.HexColor("#475569")
PALE = colors.HexColor("#F4F7FB")


def _text(value: Any) -> str:
    text = str(value if value is not None else "")
    for dash in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"):
        text = text.replace(dash, "-")
    return escape(text.replace("\u200b", ""))


def _severity_color(severity: str) -> colors.Color:
    return {"CRITICAL": RED, "HIGH": AMBER, "MEDIUM": colors.HexColor("#8A6D00"), "LOW": GREEN}.get(
        severity, SLATE
    )


def build_analysis_pdf(analysis: dict[str, Any]) -> bytes:
    result = analysis.get("result") or {}
    extraction = result.get("extraction", {})
    risk = result.get("risk", {})
    app = extraction.get("app", {})
    file_info = extraction.get("file", {})
    delta = result.get("fraud_delta", {})
    assessment = result.get("malware_assessment", {})
    engine_analysis = result.get("engine_analysis", {})
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "FraudShieldTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, textColor=NAVY
    )
    subtitle = ParagraphStyle(
        "FraudShieldSub", parent=styles["Normal"], fontSize=8, leading=11, textColor=SLATE
    )
    heading = ParagraphStyle(
        "FraudShieldHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=NAVY,
        spaceBefore=9,
        spaceAfter=5,
    )
    body = ParagraphStyle(
        "FraudShieldBody", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=colors.HexColor("#1E293B")
    )
    small = ParagraphStyle("FraudShieldSmall", parent=body, fontSize=7.5, leading=10, textColor=SLATE)
    score_style = ParagraphStyle(
        "Score", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=18, alignment=TA_CENTER
    )

    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"FraudShield APK Report {analysis['id']}",
        author="FraudShield",
    )
    story: list[Any] = [
        Paragraph("FRAUDSHIELD", title),
        Paragraph("DeceptiScope - Evidence-Grounded APK Investigation Report", subtitle),
        Spacer(1, 7),
    ]
    severity = str(risk.get("severity", analysis.get("severity", "UNKNOWN")))
    banner = Table(
        [
            [
                Paragraph(
                    f"<b>Application</b><br/>{_text(app.get('app_label', 'Unknown'))}<br/>"
                    f"<font color='#475569'>{_text(app.get('package_name', 'unknown'))}</font>",
                    body,
                ),
                Paragraph(
                    f"<font color='{_severity_color(severity).hexval()}'>{_text(risk.get('overall_score', '-'))}/100</font>"
                    f"<br/><font size='8'>{_text(severity)}</font>",
                    score_style,
                ),
            ]
        ],
        colWidths=[135 * mm, 42 * mm],
    )
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.extend([banner, Spacer(1, 6)])
    meta = [
        ["Analysis ID", analysis.get("id")],
        ["File", file_info.get("name", analysis.get("file_name"))],
        ["SHA-256", file_info.get("sha256", analysis.get("sha256"))],
        ["Category", delta.get("category", analysis.get("category"))],
        ["Evidence quality", extraction.get("analysis_quality", analysis.get("analysis_quality"))],
        ["Generated", datetime.now(timezone.utc).isoformat()],
        ["Data origin", analysis.get("data_origin")],
    ]
    meta_table = Table([[Paragraph(f"<b>{_text(k)}</b>", small), Paragraph(_text(v), small)] for k, v in meta], colWidths=[36 * mm, 141 * mm])
    meta_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 4)]))
    story.extend([meta_table, Paragraph("Malware assessment", heading)])
    story.append(
        Paragraph(
            f"<b>{_text(str(assessment.get('verdict', 'INCONCLUSIVE')).replace('_', ' '))}</b><br/>"
            f"{_text(assessment.get('explanation', 'No assessment explanation is available.'))}<br/>"
            f"<font color='#475569'>Legitimacy: {_text(assessment.get('legitimacy', 'not-established'))} | "
            f"Known malware: {_text(assessment.get('known_malware', False))} | "
            f"Safe-to-install claim: {_text(assessment.get('safe_to_install', False))}</font>",
            body,
        )
    )
    story.append(Paragraph("Deterministic risk breakdown", heading))
    sub_scores = risk.get("sub_scores", {})
    score_rows = [["Risk dimension", "Score"]] + [
        [key.replace("_", " ").title(), f"{value}/100"] for key, value in sub_scores.items()
    ]
    score_table = Table(score_rows, colWidths=[140 * mm, 37 * mm])
    score_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.append(score_table)

    story.append(Paragraph("Verified rule evidence", heading))
    for item in risk.get("evidence", []):
        artifacts = ", ".join(str(value) for value in item.get("artifacts", [])[:8])
        story.append(
            Paragraph(
                f"<b>{_text(item.get('rule_id'))} | {_text(item.get('title'))} (+{_text(item.get('points'))})</b><br/>"
                f"{_text(item.get('rationale'))}"
                + (f"<br/><font color='#475569'>Artifacts: {_text(artifacts)}</font>" if artifacts else ""),
                body,
            )
        )
        story.append(Spacer(1, 3))

    story.append(Paragraph("Fraud Delta", heading))
    story.append(
        Paragraph(
            f"Score: <b>{_text(delta.get('score'))}</b> | Anomalous: <b>{_text(delta.get('is_anomalous'))}</b><br/>"
            f"{_text(delta.get('methodology_note', ''))}",
            body,
        )
    )
    for contribution in delta.get("contributions", [])[:20]:
        story.append(
            Paragraph(
                f"- {_text(contribution.get('evidence'))} - {_text(contribution.get('reason'))}", body
            )
        )

    story.append(Paragraph("Multi-engine execution and privacy", heading))
    policy = engine_analysis.get("policy", {})
    story.append(
        Paragraph(
            f"Orchestrator: <b>{_text(engine_analysis.get('orchestrator_version', 'unknown'))}</b> | "
            f"Public binary uploads: <b>{_text(policy.get('public_binary_uploads', False))}</b> | "
            f"External hash lookups: <b>{_text(policy.get('external_hash_lookups', False))}</b><br/>"
            f"{_text(engine_analysis.get('coverage_note', ''))}",
            body,
        )
    )
    engine_rows = [["Engine", "Status", "Privacy", "Duration"]]
    for engine in engine_analysis.get("engines", [])[:20]:
        engine_rows.append(
            [
                _text(engine.get("label", engine.get("id"))),
                _text(engine.get("status")),
                _text(engine.get("privacy")),
                f"{_text(engine.get('duration_ms', 0))} ms",
            ]
        )
    engine_table = Table(engine_rows, colWidths=[67 * mm, 32 * mm, 52 * mm, 26 * mm], repeatRows=1)
    engine_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 6.8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 3.5),
            ]
        )
    )
    story.append(engine_table)
    reputation = engine_analysis.get("reputation", {})
    story.append(
        Paragraph(
            f"Hash reputation: <b>{_text(reputation.get('verdict', 'not-queried'))}</b>. "
            f"{_text(reputation.get('notice', ''))}",
            small,
        )
    )

    story.append(Spacer(1, 8))
    story.append(Paragraph("MITRE ATT&amp;CK for Mobile", heading))
    for item in result.get("mitre_attack", []):
        story.append(
            Paragraph(
                f"<b>{_text(item.get('technique_id'))} | {_text(item.get('name'))}</b><br/>"
                f"Evidence: {_text(', '.join(item.get('evidence', [])))}",
                body,
            )
        )
        story.append(Spacer(1, 3))

    story.append(Paragraph("Threat-indicator candidates", heading))
    indicators = result.get("emitted_indicators") or result.get("indicator_candidates", [])
    if indicators:
        header_style = ParagraphStyle(
            "FraudShieldTableHeader",
            parent=small,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )
        rows = [
            [
                Paragraph("Type", header_style),
                Paragraph("Value", header_style),
                Paragraph("Severity", header_style),
            ]
        ]
        for item in indicators[:40]:
            rows.append(
                [
                    Paragraph(_text(item.get("type")), small),
                    Paragraph(_text(item.get("display_value", item.get("value"))), small),
                    Paragraph(_text(item.get("severity", severity)), small),
                ]
            )
        table = Table(rows, colWidths=[34 * mm, 113 * mm, 30 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")), ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 4)]))
        story.append(table)
    else:
        story.append(Paragraph("No indicator candidate met the emission policy.", body))

    story.append(Paragraph("Analyst narrative", heading))
    for line in str(analysis.get("narrative") or "").splitlines():
        clean = line.strip()
        if clean:
            story.append(Paragraph(_text(clean), body))
            story.append(Spacer(1, 2))

    def page_footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        width, _ = A4
        line_y = 11 * mm
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.setLineWidth(0.4)
        canvas.line(document.leftMargin, line_y, width - document.rightMargin, line_y)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE)
        canvas.drawString(document.leftMargin, 7.5 * mm, f"FraudShield | {_text(analysis['id'])}")
        canvas.drawRightString(width - document.rightMargin, 7.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return output.getvalue()
