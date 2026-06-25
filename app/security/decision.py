from .models import CommandContext, RiskFactor, SecurityDecision

def risk_level_for(score: int) -> str:
    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    if score >= 15:
        return "low"

    return "minimal"

def decide_execution_strategy(context: CommandContext, risk_level: str) -> str:
    if context.has_system_target:
        return "do_not_execute"

    if context.has_outside_workspace_target:
        return "restricted_sandbox_with_confirmation"

    if context.is_destructive:
        return "workspace_sandbox_with_monitoring"

    if risk_level in ("high", "critical"):
        return "strong_sandbox"

    if risk_level == "medium":
        return "restricted_sandbox"

    return "lightweight_sandbox"

def make_decision(
    context: CommandContext,
    ai_pre_risk_score: int = 0,
) -> SecurityDecision:
    factors: list[RiskFactor] = []
    reasons: list[str] = []

    if context.uses_shell:
        factors.append(
            RiskFactor(
                name="shell_execution",
                score=25,
                reason="The command starts a shell, which can hide chained or dynamic behavior.",
            )
        )

    if context.is_destructive:
        factors.append(
            RiskFactor(
                name="destructive_command",
                score=20,
                reason="The command can delete or destroy filesystem objects.",
            )
        )

    if context.is_recursive:
        factors.append(
            RiskFactor(
                name="recursive_operation",
                score=15,
                reason="The command uses recursive behavior.",
            )
        )

    if context.is_force:
        factors.append(
            RiskFactor(
                name="force_operation",
                score=10,
                reason="The command uses force behavior.",
            )
        )

    if context.unknown_target:
        factors.append(
            RiskFactor(
                name="unknown_target",
                score=35,
                reason="The destructive command has no clear target path.",
            )
        )

    if context.has_workspace_target:
        factors.append(
            RiskFactor(
                name="inside_workspace",
                score=-20,
                reason="All target paths are inside the controlled workspace.",
            )
        )

    if context.has_outside_workspace_target:
        factors.append(
            RiskFactor(
                name="outside_workspace",
                score=25,
                reason="At least one target path is outside the controlled workspace.",
            )
        )

    if context.has_sensitive_target:
        factors.append(
            RiskFactor(
                name="sensitive_path",
                score=20,
                reason="At least one target path intersects a sensitive host path.",
            )
        )

    if context.has_system_target:
        factors.append(
            RiskFactor(
                name="critical_system_path",
                score=60,
                reason="At least one target path intersects a critical system path.",
            )
        )

    if ai_pre_risk_score > 0:
        factors.append(
            RiskFactor(
                name="ai_pre_risk",
                score=ai_pre_risk_score,
                reason="The AI pre-execution estimator raised the risk score.",
            )
        )

    raw_score = sum(item.score for item in factors)
    risk_score = max(0, min(100, raw_score))
    risk_level = risk_level_for(risk_score)
    execution_strategy = decide_execution_strategy(context, risk_level)

    for factor in factors:
        reasons.append(factor.reason)

    if context.has_system_target:
        decision = "block_critical"
        requires_confirmation = False
        can_execute = False
    elif context.is_destructive and context.has_workspace_target:
        decision = "allow_with_monitoring"
        requires_confirmation = False
        can_execute = True
    elif context.is_destructive and context.has_outside_workspace_target:
        decision = "require_confirmation"
        requires_confirmation = True
        can_execute = True
    elif risk_level in ("high", "critical"):
        decision = "review"
        requires_confirmation = True
        can_execute = True
    elif risk_level == "medium":
        decision = "review"
        requires_confirmation = True
        can_execute = True
    elif risk_level == "low":
        decision = "allow_with_monitoring"
        requires_confirmation = False
        can_execute = True
    else:
        decision = "allow"
        requires_confirmation = False
        can_execute = True

    return SecurityDecision(
        decision=decision,
        risk_score=risk_score,
        risk_level=risk_level,
        execution_strategy=execution_strategy,
        requires_confirmation=requires_confirmation,
        can_execute=can_execute,
        reasons=reasons,
        risk_factors=factors,
    )
