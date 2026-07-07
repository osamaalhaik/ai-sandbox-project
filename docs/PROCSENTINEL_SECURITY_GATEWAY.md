# ProcSentinel AI - Execution Security Gateway

## Overview
ProcSentinel AI is an AI-powered Linux runtime security sandbox platform.
The system acts as an Execution Security Gateway between the user and the operating system.
Commands are analyzed before execution using context, target paths, policy rules, runtime evidence, and risk scoring.

## Core Idea
The old model blocked commands mainly by executable name.
The new model uses context-aware security decisions.
rm -rf data/workspaces/default/cache -> allow_with_monitoring
rm -rf ./cache -> require_confirmation
rm -rf /etc -> block_critical

## Execution Flow
User Command -> ProcSentinel Gateway -> Context Analyzer -> Decision Engine -> Policy Integration -> Execution or Confirmation or Denial -> Runtime Detection -> Audit Trail -> Dashboard

## Decisions
allow
allow_with_monitoring
require_confirmation
block_critical

## Human Approval
Commands classified as require_confirmation are not executed automatically.
They are stored in data/processed/pending_approvals.jsonl.
The administrator can approve or reject them through the CLI approval tool or the Dashboard Approvals page.
Approval decisions are stored in data/processed/approval_decisions.jsonl.

## Audit Trail
Gateway decisions are stored in data/processed/gateway_decisions.jsonl.
Each record contains command, target paths, risk score, risk level, decision, execution strategy, reasons, and timestamp.

## Dashboard
The dashboard displays Gateway Decisions, Pending Approvals, Rejected Commands, Critical Blocks, Latest Gateway Decisions, Approval Audit, Runtime Analysis Runs, and Security Alerts.

## Validation
The system was validated with automated tests: Ran 76 tests OK.

## Defense Statement
ProcSentinel AI does not block commands blindly by name. It analyzes the command, target path, workspace boundary, risk factors, and policy evidence before deciding whether to allow, monitor, require approval, or block execution.
