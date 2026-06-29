import csv
import io

def security_report_to_csv(report):
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "section",
            "key",
            "value",
            "source",
            "id",
            "command",
            "risk_score",
            "risk_level",
            "decision",
            "lifecycle_status",
            "recommendation",
        ],
    )
    writer.writeheader()

    for key, value in report.get("executive_summary", {}).items():
        writer.writerow(
            {
                "section": "executive_summary",
                "key": key,
                "value": value,
            }
        )

    for key, value in report.get("analysis_run_summary", {}).get("risk_levels", {}).items():
        writer.writerow(
            {
                "section": "analysis_risk_levels",
                "key": key,
                "value": value,
            }
        )

    for key, value in report.get("analysis_run_summary", {}).get("decisions", {}).items():
        writer.writerow(
            {
                "section": "analysis_decisions",
                "key": key,
                "value": value,
            }
        )

    for key, value in report.get("gateway_summary", {}).get("risk_levels", {}).items():
        writer.writerow(
            {
                "section": "gateway_risk_levels",
                "key": key,
                "value": value,
            }
        )

    for key, value in report.get("gateway_summary", {}).get("security_decisions", {}).items():
        writer.writerow(
            {
                "section": "gateway_security_decisions",
                "key": key,
                "value": value,
            }
        )

    for item in report.get("highest_risk_items", []):
        writer.writerow(
            {
                "section": "highest_risk_items",
                "source": item.get("source", ""),
                "id": item.get("id", ""),
                "command": item.get("command", ""),
                "risk_score": item.get("risk_score", ""),
                "risk_level": item.get("risk_level", ""),
                "decision": item.get("decision", ""),
                "lifecycle_status": item.get("lifecycle_status", ""),
            }
        )

    for index, recommendation in enumerate(report.get("recommendations", []), start=1):
        writer.writerow(
            {
                "section": "recommendations",
                "key": index,
                "recommendation": recommendation,
            }
        )

    return output.getvalue()
