from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def utc_now():
    return datetime.now(timezone.utc)

class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    run_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    command_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    executable: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str | None] = mapped_column(String(80), nullable=True)
    policy_allowed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    policy_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(80), nullable=False, default="low")
    final_decision: Mapped[str] = mapped_column(String(120), nullable=False, default="allow")
    security_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    rules: Mapped[list["TriggeredRule"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )

    syscalls: Mapped[list["SyscallEvent"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )

    alerts: Mapped[list["SecurityAlert"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )

class TriggeredRule(Base):
    __tablename__ = "triggered_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.run_id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(80), nullable=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped[AnalysisRun] = relationship(back_populates="rules")

class SyscallEvent(Base):
    __tablename__ = "syscall_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.run_id"), index=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    syscall: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    raw_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped[AnalysisRun] = relationship(back_populates="syscalls")

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.run_id"), index=True)
    level: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    run: Mapped[AnalysisRun] = relationship(back_populates="alerts")


class GatewayDecisionRecord(Base):
    __tablename__ = "gateway_decisions"

    gateway_decision_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    command_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    executable: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_role: Mapped[str | None] = mapped_column(String(120), nullable=True)
    policy_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    working_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    workspace_root: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_target_paths_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_destructive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_recursive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_force: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uses_shell: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_workspace_target: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_outside_workspace_target: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_sensitive_target: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_system_target: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    security_decision: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(80), nullable=False, default="low", index=True)
    execution_strategy: Mapped[str | None] = mapped_column(String(160), nullable=True)
    requires_confirmation: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    can_execute: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    decision_status: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    final_lifecycle_status: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    risk_factors_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_admin: Mapped[str | None] = mapped_column(String(160), nullable=True)
    approval_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

class ApprovalDecisionRecord(Base):
    __tablename__ = "approval_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    gateway_decision_id: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    admin: Mapped[str | None] = mapped_column(String(160), nullable=True)
    action: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)

class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    entity_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)
