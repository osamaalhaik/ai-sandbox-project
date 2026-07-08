# ProcSentinel AI - Demo Runbook

## 1. Run Automated Tests
python -m unittest discover -s tests
Expected: Ran 84 tests OK

## 2. Run Full Security Workflow Demo
python scripts/procsentinel_demo_workflow.py

## 3. Manual Gateway Test
python scripts/procsentinel_gateway.py -- rm -rf data/workspaces/default/cache
python scripts/procsentinel_gateway.py -- rm -rf ./cache
python scripts/procsentinel_gateway.py -- rm -rf /etc

Expected decisions:
Inside workspace -> allow_with_monitoring
Outside workspace -> require_confirmation
Critical system path -> block_critical

## 4. Approval CLI
python scripts/procsentinel_approvals.py list
python scripts/procsentinel_approvals.py reject DECISION_ID --admin osama --reason "Rejected after human review."

## 5. Import Runtime Results
python scripts/import_latest_results_to_db.py

## 6. Run Dashboard
python scripts/run_dashboard.py
Open http://SERVER_IP:8010

## 7. Dashboard Sections
Gateway Decisions
Pending Approvals
Rejected Commands
Critical Blocks
Latest Gateway Decisions
Approval Audit
Runtime Analysis Runs
Security Alerts

## 8. Security Note
The dashboard exposes a command execution endpoint protected by ProcSentinel Gateway. Enable it only during development or project demonstration.

## Dashboard Authentication Demo

Authentication is disabled by default.

To enable protected dashboard access:

export PROCSENTINEL_DASHBOARD_AUTH_ENABLED=true
export PROCSENTINEL_DASHBOARD_TOKEN=procsentinel-demo-token
python scripts/run_dashboard.py

Unauthenticated access should return:

401 ProcSentinel dashboard authentication required.

Authenticated access:

http://SERVER_IP:8010/project-overview?token=procsentinel-demo-token
