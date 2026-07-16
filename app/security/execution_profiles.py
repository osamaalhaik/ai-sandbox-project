from __future__ import annotations

from dataclasses import asdict, dataclass

from app.sandbox.cgroup_v2 import (
    CgroupV2Limits,
)


@dataclass(frozen=True)
class ExecutionProfile:
    name: str
    timeout_seconds: float
    monitor_interval_seconds: float
    cpu_quota_us: int
    cpu_period_us: int
    memory_max_bytes: int
    memory_high_bytes: int | None
    memory_swap_max_bytes: int
    pids_max: int

    def resource_limits(
        self,
    ) -> CgroupV2Limits:
        return CgroupV2Limits(
            cpu_quota_us=(
                self.cpu_quota_us
            ),
            cpu_period_us=(
                self.cpu_period_us
            ),
            memory_max_bytes=(
                self.memory_max_bytes
            ),
            memory_high_bytes=(
                self.memory_high_bytes
            ),
            memory_swap_max_bytes=(
                self.memory_swap_max_bytes
            ),
            pids_max=self.pids_max,
        )

    def to_dict(self) -> dict:
        return asdict(self)


LOW_PROFILE = ExecutionProfile(
    name="low",
    timeout_seconds=15,
    monitor_interval_seconds=0.05,
    cpu_quota_us=50000,
    cpu_period_us=100000,
    memory_max_bytes=134217728,
    memory_high_bytes=None,
    memory_swap_max_bytes=0,
    pids_max=32,
)

STANDARD_PROFILE = ExecutionProfile(
    name="standard",
    timeout_seconds=30,
    monitor_interval_seconds=0.04,
    cpu_quota_us=75000,
    cpu_period_us=100000,
    memory_max_bytes=268435456,
    memory_high_bytes=234881024,
    memory_swap_max_bytes=0,
    pids_max=64,
)

INTENSIVE_PROFILE = ExecutionProfile(
    name="intensive",
    timeout_seconds=60,
    monitor_interval_seconds=0.03,
    cpu_quota_us=100000,
    cpu_period_us=100000,
    memory_max_bytes=402653184,
    memory_high_bytes=369098752,
    memory_swap_max_bytes=0,
    pids_max=128,
)

EXECUTION_PROFILES = {
    profile.name: profile
    for profile in (
        LOW_PROFILE,
        STANDARD_PROFILE,
        INTENSIVE_PROFILE,
    )
}

STRATEGY_PROFILE_MAP = {
    "lightweight_sandbox": "low",
    "workspace_sandbox_with_monitoring": (
        "standard"
    ),
    "restricted_sandbox": "standard",
    "strong_sandbox": "intensive",
    "restricted_sandbox_with_confirmation": (
        "intensive"
    ),
}

CONFIRMATION_STRATEGIES = {
    "restricted_sandbox_with_confirmation",
}

BLOCKED_STRATEGIES = {
    "do_not_execute",
}


def profile_for_strategy(
    execution_strategy: str,
) -> ExecutionProfile:
    normalized = str(
        execution_strategy or ""
    ).strip()

    if normalized in BLOCKED_STRATEGIES:
        raise ValueError(
            "Execution strategy is blocked"
        )

    profile_name = (
        STRATEGY_PROFILE_MAP.get(
            normalized
        )
    )

    if profile_name is None:
        raise ValueError(
            "Unknown execution strategy: "
            f"{normalized or '<empty>'}"
        )

    return EXECUTION_PROFILES[
        profile_name
    ]


def strategy_requires_approval(
    execution_strategy: str,
) -> bool:
    return (
        execution_strategy
        in CONFIRMATION_STRATEGIES
    )
