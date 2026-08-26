from __future__ import annotations

import io
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


NAVY = colors.HexColor("#0B1930")
BLUE = colors.HexColor("#1677FF")
CYAN = colors.HexColor("#0891B2")
RED = colors.HexColor("#C62828")
AMBER = colors.HexColor("#B26A00")
GREEN = colors.HexColor("#18794E")
PURPLE = colors.HexColor("#6D28D9")
SLATE = colors.HexColor("#475569")
PALE = colors.HexColor("#F4F7FB")
BORDER_GREY = colors.HexColor("#CBD5E1")


def _text(value: Any) -> str:
    text = str(value if value is not None else "")
    for dash in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"):
        text = text.replace(dash, "-")
    return escape(text.replace("\u200b", ""))


def _severity_color(severity: str) -> colors.Color:
    return {
        "CRITICAL": RED,
        "HIGH": AMBER,
        "MEDIUM": colors.HexColor("#8A6D00"),
        "LOW": GREEN,
        "LOW_RISK_OBSERVED": GREEN,
    }.get(severity.upper(), SLATE)


from fraudshield.deceptiscope.impact import derive_banking_impact


def build_analysis_pdf(analysis: dict[str, Any]) -> bytes:
    result = analysis.get("result") or {}
    extraction = result.get("extraction", {})
    risk = result.get("risk", {})
    app = extraction.get("app", {})
    file_info = extraction.get("file", {})
    assessment = result.get("malware_assessment", {})
    ai_investigation = result.get("ai_investigation", {})
    runtime_evidence = result.get("runtime_evidence", [])
    recovered_payloads = result.get("recovered_payloads", [])
    campaign = result.get("campaign", {})
    related_samples = result.get("related_samples", [])
    brand_impersonation = result.get("brand_impersonation", {})
    firebase_infra = result.get("firebase_infrastructure", {})
    banking_impact = result.get("banking_impact") or derive_banking_impact(result)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("RptTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, textColor=NAVY, alignment=TA_LEFT)
    sub_style = ParagraphStyle("RptSub", parent=styles["Normal"], fontSize=8.5, leading=11, textColor=SLATE)
    sec_heading = ParagraphStyle("RptSecHead", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=NAVY, spaceBefore=8, spaceAfter=4)
    body = ParagraphStyle("RptBody", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#1E293B"))
    small = ParagraphStyle("RptSmall", parent=body, fontSize=7, leading=9, textColor=SLATE)
    score_big = ParagraphStyle("RptScore", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=16, alignment=TA_CENTER)

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"FraudShield Investigation Report {analysis.get('id', '')}",
        author="FraudShield DeceptiScope",
    )
    story: list[Any] = []

    # =========================================================================
    # 1. EXECUTIVE FRAUD ASSESSMENT (PAGE 1)
    # =========================================================================
    story.append(Paragraph("FRAUDSHIELD DECEPTISCOPE 3.0", title_style))
    story.append(Paragraph("Evidence-Grounded APK Investigation &amp; Banking Threat Intelligence Report", sub_style))
    story.append(Spacer(1, 4))

    severity = str(risk.get("severity", analysis.get("severity", "UNKNOWN")))
    static_score = risk.get("static_score", risk.get("overall_score", "-"))
    runtime_adj = risk.get("runtime_adjustment", 0)
    overall_score = risk.get("overall_score", "-")
    conf_pct = int((risk.get("confidence", 0.9)) * 100)
    runtime_conf_pct = int((risk.get("runtime_confirmation", 0.0)) * 100)

    banner_data = [
        [
            Paragraph(
                f"<b>Application Target:</b> {_text(app.get('app_label', 'Unknown'))}<br/>"
                f"<font color='#475569'><b>Package:</b> {_text(app.get('package_name', 'unknown'))}</font><br/>"
                f"<font size='6.5' color='#64748B'><b>SHA-256:</b> {_text(file_info.get('sha256', analysis.get('sha256', '')))}</font>",
                body,
            ),
            Paragraph(
                f"<font color='{_severity_color(severity).hexval()}'><b>{_text(overall_score)}/100</b></font><br/>"
                f"<font size='8' color='{_severity_color(severity).hexval()}'><b>{_text(severity)}</b></font>",
                score_big,
            ),
        ]
    ]
    banner = Table(banner_data, colWidths=[138 * mm, 44 * mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(banner)
    story.append(Spacer(1, 4))

    # Two-Stage Score Progression
    progression_data = [
        [
            Paragraph(f"<b>Static Risk:</b> <font color='#1677FF'>{_text(static_score)}</font>", body),
            Paragraph(f"<b>Verified Runtime Adj:</b> <font color='#18794E'>+{_text(runtime_adj)}</font>", body),
            Paragraph(f"<b>Final Fraud Score:</b> <font color='{_severity_color(severity).hexval()}'><b>{_text(overall_score)}</b></font>", body),
            Paragraph(f"<b>Runtime Proof:</b> {runtime_conf_pct}%", body),
        ]
    ]
    prog_table = Table(progression_data, colWidths=[45 * mm, 45 * mm, 47 * mm, 45 * mm])
    prog_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_GREY),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(prog_table)
    story.append(Spacer(1, 4))

    # Executive Summary Box
    impact_items = banking_impact.get("items", [])
    confirmed_titles = [it.get("title", "") for it in impact_items if it.get("status") == "CONFIRMED"]
    supported_titles = [it.get("title", "") for it in impact_items if it.get("status") == "SUPPORTED"]
    if confirmed_titles:
        primary_threat = f"Confirmed: {', '.join(confirmed_titles[:2])}"
    elif supported_titles:
        primary_threat = f"Supported: {', '.join(supported_titles[:2])}"
    else:
        primary_threat = "Low Risk / No High-Impact Fraud Proven"

    camp_str = f"Campaign {campaign.get('campaign_id')}" if campaign else "Single Isolated Sample"
    exec_meta = [
        ["Investigation ID", _text(analysis.get("id"))],
        ["Primary Threat", primary_threat],
        ["Malware Verdict", _text(str(assessment.get("verdict", "INCONCLUSIVE")).replace("_", " "))],
        ["Threat Cluster", f"{camp_str} ({len(related_samples)} correlated APKs)"],
        ["Analysis Model", f"apk-risk-2026.5 (confidence: {conf_pct}%)"],
        ["Data Origin", _text(analysis.get("data_origin", "production"))],
    ]
    exec_table = Table([[Paragraph(f"<b>{_text(k)}</b>", small), Paragraph(_text(v), small)] for k, v in exec_meta], colWidths=[36 * mm, 146 * mm])
    exec_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
    ]))
    story.append(exec_table)

    # =========================================================================
    # 2. BANKING IMPACT & INVESTIGATION SUMMARY
    # =========================================================================
    story.append(Paragraph("1. Banking Fraud Impact Matrix", sec_heading))
    impact_rows = [["Banking Capability", "Status", "Deterministic Evidence Basis"]]
    for item in impact_items:
        basis_text = item.get("deterministic_basis", "")
        ev_ids = item.get("evidence_ids", [])
        if ev_ids:
            basis_text = f"{basis_text} [IDs: {', '.join(ev_ids[:3])}]"
        impact_rows.append([
            item.get("title", item.get("category", "")),
            item.get("status", "NOT_OBSERVED"),
            basis_text,
        ])
    impact_table = Table([[Paragraph(f"<b>{_text(c)}</b>" if i == 0 else _text(c), small) for c in row] for i, row in enumerate(impact_rows)], colWidths=[44 * mm, 30 * mm, 108 * mm])
    impact_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
        ("PADDING", (0, 0), (-1, -1), 3.5),
    ]))
    story.append(impact_table)

    # =========================================================================
    # 3. CONFIRMED BEHAVIORS & AI HYPOTHESES
    # =========================================================================
    story.append(Paragraph("2. AI Hypotheses &amp; Deterministic Verifications", sec_heading))
    hypotheses = ai_investigation.get("hypotheses", [])
    if hypotheses:
        for hyp in hypotheses[:3]:
            story.append(Paragraph(
                f"<b>Hypothesis {hyp.get('hypothesis_id')}: {_text(hyp.get('title'))}</b> "
                f"<font color='#6D28D9'>[{_text(hyp.get('status'))} · Conf: {int(hyp.get('confidence', 0)*100)}%]</font><br/>"
                f"{_text(hyp.get('reasoning_summary'))}<br/>"
                f"<font color='#475569'><b>Supporting IDs:</b> {', '.join(hyp.get('supporting_evidence_ids', []))} | "
                f"<b>Experiments:</b> {', '.join(hyp.get('recommended_experiment_types', []))}</font>",
                small,
            ))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No AI hypotheses were emitted for this sample.", small))

    # =========================================================================
    # 4. RUNTIME EXPERIMENTS & DATA-LINEAGE CORRELATION
    # =========================================================================
    story.append(Paragraph("3. Runtime Experiments &amp; Synthetic Data-Lineage", sec_heading))
    if runtime_evidence:
        re_rows = [["ID", "Trust Level", "Event Type", "API / Observation"]]
        for re_item in runtime_evidence[:6]:
            re_rows.append([
                _text(re_item.get("evidence_id")),
                _text(re_item.get("trust_level")),
                _text(re_item.get("event_type")),
                _text(re_item.get("description")),
            ])
        re_table = Table([[Paragraph(f"<b>{_text(c)}</b>" if i == 0 else _text(c), small) for c in row] for i, row in enumerate(re_rows)], colWidths=[18 * mm, 32 * mm, 38 * mm, 94 * mm])
        re_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(re_table)
    else:
        story.append(Paragraph("No runtime observations were recorded (static analysis only).", small))

    # =========================================================================
    # 5. RECOVERED PAYLOADS
    # =========================================================================
    if recovered_payloads:
        story.append(Paragraph(f"4. Recovered Secondary Payloads ({len(recovered_payloads)})", sec_heading))
        for pl in recovered_payloads:
            caps = ", ".join(pl.get("extracted_capabilities", [])) or "None"
            story.append(Paragraph(
                f"<b>{_text(pl.get('payload_id'))} [{_text(pl.get('payload_type'))}]</b> · Loader: <font color='#1677FF'>{_text(pl.get('loader'))}</font> · Size: {(pl.get('size_bytes', 0)/1024):.1f} KB<br/>"
                f"<font size='6.5' color='#64748B'>SHA-256: {_text(pl.get('sha256'))}</font><br/>"
                f"<b>Discovered Secondary Capabilities:</b> {_text(caps)}",
                small,
            ))
            story.append(Spacer(1, 2))

    # =========================================================================
    # 6. FRAUDDNA & CAMPAIGN CORRELATION
    # =========================================================================
    story.append(Paragraph("5. FraudDNA &amp; Threat Campaign Correlation", sec_heading))
    if related_samples:
        rel_rows = [["Related SHA-256", "Similarity", "Campaign", "Linkage Reasons"]]
        for rel in related_samples[:4]:
            reasons_str = ", ".join(rel.get("reasons", []))
            rel_rows.append([
                _text(rel.get("sha256", "")[:24] + "..."),
                f"{int(rel.get('similarity', 0)*100)}%",
                _text(rel.get("campaign_id", "-")),
                _text(reasons_str),
            ])
        rel_table = Table([[Paragraph(f"<b>{_text(c)}</b>" if i == 0 else _text(c), small) for c in row] for i, row in enumerate(rel_rows)], colWidths=[42 * mm, 20 * mm, 24 * mm, 96 * mm])
        rel_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(rel_table)
    else:
        story.append(Paragraph("No cross-sample correlation links met the campaign threshold.", small))

    # =========================================================================
    # 7. BANK IMPERSONATION & FIREBASE INFRASTRUCTURE
    # =========================================================================
    story.append(Paragraph("6. Banking-Brand Impersonation &amp; Infrastructure", sec_heading))
    target_bank = brand_impersonation.get("target_bank_name") or "None"
    imp_verdict = brand_impersonation.get("verdict") or "NONE"
    fb_project = firebase_infra.get("project_id") or "None"
    story.append(Paragraph(
        f"<b>Target Brand:</b> {_text(target_bank)} | <b>Verdict:</b> <font color='{_severity_color(imp_verdict).hexval()}'><b>{_text(imp_verdict)}</b></font> | "
        f"<b>Title Match:</b> {int(brand_impersonation.get('app_label_similarity', 0)*100)}% | <b>Signer Verified:</b> {brand_impersonation.get('is_trusted_signer', False)}<br/>"
        f"<b>Firebase Backend Project:</b> <font color='#0891B2'><b>{_text(fb_project)}</b></font> | "
        f"<b>Endpoint:</b> {_text(firebase_infra.get('firebase_url', 'None'))}",
        small,
    ))

    # =========================================================================
    # 8. RECOMMENDED RESPONSE ACTIONS
    # =========================================================================
    story.append(Paragraph("7. Recommended Bank Response &amp; Playbook", sec_heading))
    playbook = [
        "1. Block sample SHA-256 hash across perimeter WAF and EDR endpoint agents.",
        f"2. Submit brand takedown notice for domain/C2 endpoints ({', '.join(extraction.get('network_indicators', {}).get('domains', [])[:2]) or 'infringing domains'}).",
        f"3. File credential harvesting abuse report for Firebase project '{fb_project}'.",
        "4. Enforce mandatory out-of-band biometric/hardware MFA challenge on enrolled customer sessions.",
    ]
    for action in playbook:
        story.append(Paragraph(_text(action), small))

    # =========================================================================
    # 9. THREAT INDICATORS & IOCS
    # =========================================================================
    story.append(Paragraph("8. Threat Indicators &amp; IOCs", sec_heading))
    indicators = result.get("emitted_indicators") or result.get("indicator_candidates", [])
    if indicators:
        ioc_rows = [["Type", "Indicator Value", "Severity"]]
        for item in indicators[:8]:
            ioc_rows.append([
                _text(item.get("type")),
                _text(item.get("display_value", item.get("value"))),
                _text(item.get("severity", severity)),
            ])
        ioc_table = Table([[Paragraph(f"<b>{_text(c)}</b>" if i == 0 else _text(c), small) for c in row] for i, row in enumerate(ioc_rows)], colWidths=[30 * mm, 122 * mm, 30 * mm])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
            ("PADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(ioc_table)
    else:
        story.append(Paragraph("No indicators met the emission policy threshold.", small))

    # =========================================================================
    # 10. MITRE ATT&CK MOBILE
    # =========================================================================
    story.append(Paragraph("9. MITRE ATT&amp;CK for Mobile", sec_heading))
    for item in result.get("mitre_attack", [])[:4]:
        story.append(Paragraph(
            f"<b>{_text(item.get('technique_id'))}: {_text(item.get('name'))}</b> — {_text(', '.join(item.get('evidence', [])))}",
            small,
        ))

    # =========================================================================
    # 11. ANALYST EXECUTIVE NARRATIVE
    # =========================================================================
    story.append(Paragraph("10. Analyst Executive Narrative", sec_heading))
    narrative_text = str(analysis.get("narrative") or "No narrative summary generated.")
    for line in narrative_text.splitlines()[:12]:
        clean = line.strip()
        if clean:
            story.append(Paragraph(_text(clean), small))
            story.append(Spacer(1, 1.5))

    # Footer
    def page_footer(canvas: Any, d: Any) -> None:
        canvas.saveState()
        width, _ = A4
        line_y = 10 * mm
        canvas.setStrokeColor(BORDER_GREY)
        canvas.setLineWidth(0.4)
        canvas.line(doc.leftMargin, line_y, width - doc.rightMargin, line_y)
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(SLATE)
        canvas.drawString(doc.leftMargin, 7 * mm, f"FraudShield DeceptiScope 3.0 | Investigation: {_text(analysis.get('id', ''))}")
        canvas.drawRightString(width - doc.rightMargin, 7 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return output.getvalue()
