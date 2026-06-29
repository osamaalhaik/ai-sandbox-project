from collections import Counter

def safe_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0

def risk_bucket(score):
    score = safe_int(score)

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "suspicious"

    return "low"

def summarize_runs(runs):
    risk_levels = Counter()
    decisions = Counter()
    highest = []

    for item in runs:
        risk_level = str(item.get("risk_level") or risk_bucket(item.get("risk_score")))
        decision = str(item.get("decision") or item.get("final_decision") or "unknown")
        risk_levels[risk_level] += 1
        decisions[decision] += 1
        highest.append(
            {
                "source": "analysis_run",
                "id": item.get("run_id"),
                "command": item.get("command"),
                "risk_score": safe_int(item.get("risk_score")),
                "risk_level": risk_level,
                "decision": decision,
            }
        )

    return {
        "risk_levels": dict(risk_levels),
        "decisions": dict(decisions),
        "highest_risk_items": sorted(highest, key=lambda item: item["risk_score"], reverse=True)[:5],
    }

def summarize_gateway(decisions):
    risk_levels = Counter()
    security_decisions = Counter()
    lifecycle = Counter()
    highest = []

    for item in decisions:
        risk_level = str(item.get("risk_level") or risk_bucket(item.get("risk_score")))
        security_decision = str(item.get("security_decision") or "unknown")
        lifecycle_status = str(item.get("final_lifecycle_status") or item.get("decision_status") or "unknown")
        risk_levels[risk_level] += 1
        security_decisions[security_decision] += 1
        lifecycle[lifecycle_status] += 1
        highest.append(
            {
                "source": "gateway_decision",
                "id": item.get("gateway_decision_id"),
                "command": item.get("command_text"),
                "risk_score": safe_int(item.get("risk_score")),
                "risk_level": risk_level,
                "decision": security_decision,
                "lifecycle_status": lifecycle_status,
            }
        )

    return {
        "risk_levels": dict(risk_levels),
        "security_decisions": dict(security_decisions),
        "lifecycle_statuses": dict(lifecycle),
        "highest_risk_items": sorted(highest, key=lambda item: item["risk_score"], reverse=True)[:5],
    }

def build_recommendations(stats, gateway_summary):
    recommendations = []

    if safe_int(stats.get("critical_blocks")) > 0:
        recommendations.append("Keep critical command blocking enabled for system and sensitive filesystem paths.")

    if safe_int(stats.get("pending_approvals")) > 0:
        recommendations.append("Review pending approvals before allowing any high-risk command execution.")

    if safe_int(stats.get("alerts")) > 0:
        recommendations.append("Preserve alerts and audit records as evidence for the project defense.")

    if safe_int(stats.get("sensitive_path_events")) > 0:
        recommendations.append("Highlight sensitive path detection in the live demonstration.")

    if gateway_summary.get("security_decisions", {}).get("allow_with_monitoring", 0) > 0:
        recommendations.append("Use monitored workspace execution as the safe path for controlled destructive commands.")

    if not recommendations:
        recommendations.append("The current environment is stable and ready for demonstration.")

    return recommendations

def build_security_report(stats, runs, gateway_decisions, approval_decisions, alerts, generated_at):
    run_summary = summarize_runs(runs)
    gateway_summary = summarize_gateway(gateway_decisions)
    combined_highest = sorted(
        run_summary["highest_risk_items"] + gateway_summary["highest_risk_items"],
        key=lambda item: item["risk_score"],
        reverse=True,
    )[:10]

    return {
        "report_name": "ProcSentinel Security Summary Report",
        "generated_at": generated_at,
        "executive_summary": {
            "total_runs": safe_int(stats.get("total_runs")),
            "allowed": safe_int(stats.get("allowed")),
            "reviewed": safe_int(stats.get("reviewed")),
            "blocked_or_investigate": safe_int(stats.get("blocked_or_investigate")),
            "alerts": safe_int(stats.get("alerts")),
            "sensitive_path_events": safe_int(stats.get("sensitive_path_events")),
            "total_gateway_decisions": safe_int(stats.get("total_gateway_decisions")),
            "pending_approvals": safe_int(stats.get("pending_approvals")),
            "critical_blocks": safe_int(stats.get("critical_blocks")),
        },
        "analysis_run_summary": run_summary,
        "gateway_summary": gateway_summary,
        "approval_summary": {
            "total_records": len(approval_decisions),
            "latest": approval_decisions[:10],
        },
        "alert_summary": {
            "total_records": len(alerts),
            "latest": alerts[:10],
        },
        "highest_risk_items": combined_highest,
        "recommendations": build_recommendations(stats, gateway_summary),
    }
