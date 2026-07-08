from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class AIEvaluationScenario:
    name: str
    command: str
    context_classification: str
    rule_based_risk: str
    ai_prediction: str
    ai_risk_level: str
    final_decision: str
    explanation: str


DEFAULT_AI_EVALUATION_SCENARIOS = (
    AIEvaluationScenario(
        name="safe_workspace_command",
        command="rm -rf data/workspaces/default/cache",
        context_classification="inside_workspace",
        rule_based_risk="low",
        ai_prediction="normal",
        ai_risk_level="low",
        final_decision="allow_with_monitoring",
        explanation="The command targets the controlled workspace, so it can be allowed with monitoring.",
    ),
    AIEvaluationScenario(
        name="outside_workspace_command",
        command="rm -rf ./cache",
        context_classification="outside_workspace",
        rule_based_risk="high",
        ai_prediction="anomaly",
        ai_risk_level="suspicious",
        final_decision="require_confirmation",
        explanation="The command is destructive and escapes the workspace boundary, so human review is required.",
    ),
    AIEvaluationScenario(
        name="sensitive_path_access",
        command="cat /etc/passwd",
        context_classification="sensitive_path",
        rule_based_risk="suspicious",
        ai_prediction="anomaly",
        ai_risk_level="suspicious",
        final_decision="review",
        explanation="The command accesses a sensitive security file, so it should be reviewed and audited.",
    ),
    AIEvaluationScenario(
        name="critical_system_path_delete",
        command="rm -rf /etc",
        context_classification="critical_path",
        rule_based_risk="critical",
        ai_prediction="anomaly",
        ai_risk_level="high",
        final_decision="block_critical",
        explanation="The command targets a critical Linux path and must be blocked before execution.",
    ),
)


def build_ai_evaluation_rows(
    scenarios: Iterable[AIEvaluationScenario] = DEFAULT_AI_EVALUATION_SCENARIOS,
) -> list[dict]:
    return [asdict(scenario) for scenario in scenarios]


def summarize_ai_evaluation(rows: list[dict]) -> dict:
    total = len(rows)
    anomaly_count = sum(1 for row in rows if row["ai_prediction"] == "anomaly")
    normal_count = sum(1 for row in rows if row["ai_prediction"] == "normal")
    blocked_count = sum(1 for row in rows if row["final_decision"] == "block_critical")
    review_count = sum(1 for row in rows if row["final_decision"] in {"review", "require_confirmation"})
    allow_count = sum(1 for row in rows if row["final_decision"].startswith("allow"))

    return {
        "total_scenarios": total,
        "ai_normal_predictions": normal_count,
        "ai_anomaly_predictions": anomaly_count,
        "final_allow_decisions": allow_count,
        "final_review_decisions": review_count,
        "final_block_decisions": blocked_count,
        "positioning": "AI is used as an assistant signal and is not the sole source of the final security decision.",
    }


def build_ai_evaluation_report() -> dict:
    rows = build_ai_evaluation_rows()
    return {
        "title": "ProcSentinel AI - AI Evaluation Evidence",
        "summary": summarize_ai_evaluation(rows),
        "scenarios": rows,
    }
