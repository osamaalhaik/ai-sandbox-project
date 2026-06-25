from dataclasses import dataclass, field
from pathlib import Path

@dataclass(frozen=True)
class CommandContext:
    command: list[str]
    executable: str
    working_directory: Path
    workspace_root: Path
    target_paths: list[Path]
    resolved_target_paths: list[Path]
    is_destructive: bool
    is_recursive: bool
    is_force: bool
    uses_shell: bool
    has_sensitive_target: bool
    has_system_target: bool
    has_outside_workspace_target: bool
    has_workspace_target: bool
    unknown_target: bool
    user_role: str
    policy_name: str

@dataclass(frozen=True)
class RiskFactor:
    name: str
    score: int
    reason: str

@dataclass(frozen=True)
class SecurityDecision:
    decision: str
    risk_score: int
    risk_level: str
    execution_strategy: str
    requires_confirmation: bool
    can_execute: bool
    reasons: list[str] = field(default_factory=list)
    risk_factors: list[RiskFactor] = field(default_factory=list)
