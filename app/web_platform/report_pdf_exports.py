from datetime import datetime, timezone

def _escape_pdf_text(value):
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("(", "\\(")
    text = text.replace(")", "\\)")
    return text

def _safe(value):
    if value is None:
        return ""
    return str(value)

def _append_wrapped(lines, text, width=92):
    current = str(text).strip()
    while len(current) > width:
        split_at = current.rfind(" ", 0, width)
        if split_at <= 0:
            split_at = width
        lines.append(current[:split_at].strip())
        current = current[split_at:].strip()
    if current:
        lines.append(current)

def security_report_to_text_lines(report):
    lines = []
    lines.append("ProcSentinel AI - Security Summary Report")
    lines.append("Generated At: " + _safe(report.get("generated_at", datetime.now(timezone.utc).isoformat())))
    lines.append("")

    summary = report.get("executive_summary", {})
    lines.append("Executive Summary")
    for key in sorted(summary):
        lines.append(f"{key}: {summary.get(key)}")
    lines.append("")

    analysis = report.get("analysis_run_summary", {})
    lines.append("Analysis Run Summary")
    lines.append("Risk Levels")
    for key, value in analysis.get("risk_levels", {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("Decisions")
    for key, value in analysis.get("decisions", {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("")

    gateway = report.get("gateway_summary", {})
    lines.append("Gateway Summary")
    lines.append("Risk Levels")
    for key, value in gateway.get("risk_levels", {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("Security Decisions")
    for key, value in gateway.get("security_decisions", {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("Lifecycle Statuses")
    for key, value in gateway.get("lifecycle_statuses", {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("")

    approvals = report.get("approval_summary", {})
    lines.append("Approval Summary")
    lines.append("total_records: " + _safe(approvals.get("total_records", 0)))
    for item in approvals.get("latest", [])[:5]:
        command = item.get("command_text", "")
        status = item.get("approval_status", "")
        risk_score = item.get("risk_score", "")
        risk_level = item.get("risk_level", "")
        _append_wrapped(lines, f"- {status} | {risk_score}/{risk_level} | {command}")
    lines.append("")

    alerts = report.get("alert_summary", {})
    lines.append("Alert Summary")
    lines.append("total_records: " + _safe(alerts.get("total_records", 0)))
    for item in alerts.get("latest", [])[:8]:
        level = item.get("level", "")
        title = item.get("title", "")
        message = item.get("message", "")
        _append_wrapped(lines, f"- {level} | {title} | {message}")
    lines.append("")

    lines.append("Highest Risk Items")
    for item in report.get("highest_risk_items", [])[:10]:
        source = item.get("source", "")
        command = item.get("command", "")
        risk_score = item.get("risk_score", "")
        risk_level = item.get("risk_level", "")
        decision = item.get("decision", "")
        status = item.get("lifecycle_status", "")
        _append_wrapped(lines, f"- {source} | {risk_score}/{risk_level} | {decision} | {status} | {command}")
    lines.append("")

    lines.append("Recommendations")
    for item in report.get("recommendations", []):
        _append_wrapped(lines, "- " + str(item))

    return lines

def _paginate(lines, max_lines=42):
    pages = []
    current = []
    for line in lines:
        current.append(line)
        if len(current) >= max_lines:
            pages.append(current)
            current = []
    if current:
        pages.append(current)
    return pages or [["ProcSentinel AI - Security Summary Report"]]

def security_report_to_pdf_bytes(report):
    lines = security_report_to_text_lines(report)
    pages = _paginate(lines)

    objects = []
    page_refs = []

    def add_object(content):
        objects.append(content)
        return len(objects)

    catalog_id = add_object("")
    pages_id = add_object("")
    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for page_lines in pages:
        content_parts = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
        first = True
        for line in page_lines:
            escaped = _escape_pdf_text(line)
            if first:
                content_parts.append(f"({escaped}) Tj")
                first = False
            else:
                content_parts.append("T*")
                content_parts.append(f"({escaped}) Tj")
        content_parts.append("ET")
        stream = "\n".join(content_parts).encode("latin-1", errors="replace")
        content_id = add_object(f"<< /Length {len(stream)} >>\nstream\n" + stream.decode("latin-1") + "\nendstream")
        page_id = add_object(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>")
        page_refs.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_refs)
    objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>"
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_refs)} >>"

    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")
    offsets = [0]

    for index, content in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("latin-1"))
        pdf.extend(content.encode("latin-1", errors="replace"))
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

    pdf.extend(b"trailer\n")
    pdf.extend(f"<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n".encode("latin-1"))
    pdf.extend(b"startxref\n")
    pdf.extend(f"{xref_start}\n".encode("latin-1"))
    pdf.extend(b"%%EOF\n")

    return bytes(pdf)
