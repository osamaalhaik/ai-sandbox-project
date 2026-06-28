# ProcSentinel AI - Database Layer

## Overview

ProcSentinel AI uses a SQLite database for the academic prototype. The database stores imported runtime analysis results, security gateway decisions, human approval decisions, syscall events, triggered rules, alerts, and audit events.

The default database file is:

data/security_platform.db

The database is created through SQLAlchemy models and can later be migrated to PostgreSQL for production deployment.

## Database Initialization

Run:

python scripts/init_security_database.py

This creates the database schema using SQLAlchemy metadata.

## JSONL Import

Runtime analysis results are imported through:

python scripts/import_latest_results_to_db.py

Security Gateway and approval records are imported through:

python scripts/import_gateway_records_to_db.py

## Main Tables

analysis_runs:
Stores process execution and behavioral analysis summaries.

triggered_rules:
Stores detection rules triggered for each analysis run.

syscall_events:
Stores parsed syscall-level events linked to analysis runs.

security_alerts:
Stores generated security alerts.

gateway_decisions:
Stores context-aware Execution Security Gateway decisions.

approval_decisions:
Stores human approval or rejection decisions.

audit_events:
Stores auditable events generated from gateway and approval imports.

## Current Verified Import

The verified local database contains:

analysis_runs = 13
triggered_rules = 10
syscall_events = 1001
security_alerts = 6
gateway_decisions = 3
approval_decisions = 1
audit_events = 4

## Gateway Decision Examples

allow_with_monitoring:
A destructive command targeting the controlled workspace is allowed with monitoring.

require_confirmation:
A destructive command outside the workspace requires human confirmation.

block_critical:
A destructive command targeting a critical system path is denied.

## Prototype Scope

SQLite is suitable for the university prototype because it requires no external database server and works locally during demonstration.

## Production Roadmap

Future production-level improvements include:

- PostgreSQL persistence
- database migrations
- authenticated dashboard access
- role-based access control
- audit log retention policies
- exportable reports
