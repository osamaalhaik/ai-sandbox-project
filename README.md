# AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

## Overview

This project is a Linux behavioral security prototype for running processes through a controlled sandbox pipeline, monitoring runtime behavior, tracing system calls with strace, extracting behavioral features, applying rule-based detection, and producing a final security risk score.

The project focuses on behavioral analysis instead of static malware signatures.

## Current Capabilities

- Command execution policy
- Runtime resource limits
- Process monitoring
- Process sample summarization
- strace syscall tracing
- Syscall event parsing
- Syscall summary generation
- Behavioral feature extraction
- Rule-based detection
- Trace-aware detection pipeline
- Demo scenarios
- Automated tests

## Final Pipeline

Command Input
→ Command Policy
→ Sandbox Execution
→ Process Monitoring
→ strace Syscall Tracing
→ Process Summary
→ Syscall Summary
→ Behavioral Feature Extraction
→ Rule-Based Detection
→ Risk Score

## Risk Levels

0 - 29    low
30 - 69   suspicious
70 - 100  high

## Main Detection Rules

- POLICY_BLOCKED_COMMAND
- PROCESS_TIMEOUT
- NON_ZERO_EXIT
- HIGH_RSS_MEMORY_USAGE
- HIGH_OPEN_FILES_USAGE
- HIGH_CHILD_PROCESS_COUNT
- SENSITIVE_PATH_ACCESS
- NETWORK_ACTIVITY_OBSERVED
- FAILED_SYSCALL_ACTIVITY

## Project Structure

app/sandbox       Command policy and sandbox runner
app/monitoring    Process monitoring and sample summaries
app/tracing       strace parsing and syscall summaries
app/features      Behavioral feature extraction
app/detection     Rule-based detection engine
scripts           CLI runners and demo scripts
tests             Automated tests
docs              Architecture, demo guide, and report
data              Runtime JSONL outputs

## Setup

cd ~/ai-sandbox-project
source venv/bin/activate
pip install -r requirements.txt

## Run Tests

python -m unittest discover -s tests -p "test_*.py"

Expected result:

Ran 80 tests
OK

## Run Basic Demo Scenarios

python scripts/run_demo_scenarios.py --scenario all

This runs:

- safe process
- timeout process
- blocked dangerous command

## Run Trace-Aware Pipeline

Safe process:

python scripts/run_trace_aware_pipeline.py --monitor-interval 0.1 -- python scripts/demo_safe_process.py

Blocked command:

python scripts/run_trace_aware_pipeline.py -- rm -rf /tmp/trace-aware-blocked-test

## Expected Trace-Aware Results

Safe process:

status = completed
risk_score = 0
risk_level = low
triggered_rules_count = 0

Blocked command:

status = blocked
risk_score = 70
risk_level = high
triggered_rule = POLICY_BLOCKED_COMMAND

## Output Files

data/raw/sandbox_runs.jsonl
data/raw/process_samples.jsonl
data/raw/syscall_events.jsonl
data/raw/trace_aware_runs.jsonl
data/processed/process_sample_summaries.jsonl
data/processed/syscall_summaries.jsonl
data/processed/behavioral_features.jsonl
data/processed/detection_results.jsonl
data/processed/demo_results.jsonl

## Documentation

docs/ARCHITECTURE.md
docs/COMPONENTS.md
docs/ROADMAP.md
docs/DEMO_GUIDE.md
docs/PROJECT_REPORT.md

## Current Status

The current version is a working academic prototype with a full trace-aware behavioral detection pipeline, context-aware security gateway, dashboard/API layer, AI anomaly detection support, and 62 passing automated tests.

## Current Completed Extensions

- Improved trace-aware demo scenarios
- Added syscall-based sensitive path access demo
- Added SQLite-backed dashboard data support
- Added Web Dashboard and API layer
- Added AI anomaly detection layer
- Added Context-Aware Execution Security Gateway
- Added Human Approval workflow
- Added Audit Trail for gateway and approval decisions

## Next Planned Work

- Strengthen Linux isolation using namespaces, cgroups, and seccomp
- Add authentication and role-based access control for the dashboard
- Improve AI model evaluation with larger behavioral datasets
- Improve security report layout and add richer dashboard visualizations
- Add SIEM integration and external alert notifications

## Final Unified Demo

Run the final unified demo:

python scripts/run_final_demo.py --scenario all --reset-data

Expected scenarios:

safe process:
risk_score = 0
risk_level = low
passed = true

sensitive path access:
risk_score = 45
risk_level = suspicious
triggered_rule = SENSITIVE_PATH_ACCESS
passed = true

blocked command:
risk_score = 70
risk_level = high
triggered_rule = POLICY_BLOCKED_COMMAND
passed = true

## Final Three-Layer Architecture

The project is implemented as a three-layer system.

### Layer 1: Systems Layer

This layer handles controlled Linux process execution and runtime observation.

Main outputs:

- systems_status
- total_syscalls
- file_syscalls_count
- process_syscalls_count
- network_syscalls_count

### Layer 2: Cybersecurity Layer

This layer applies security policy, rule-based detection, and risk scoring.

Main outputs:

- cybersecurity_risk_score
- cybersecurity_risk_level
- cybersecurity_triggered_rules
- security explanation

### Layer 3: AI Layer

This layer applies machine learning-based anomaly detection using IsolationForest.

Main outputs:

- ai_anomaly_score
- ai_prediction
- ai_risk_level
- ai_explanation

## Final Demo Command

python scripts/run_final_demo.py --scenario all --reset-data

Expected final decisions:

safe      -> allow
sensitive -> review
blocked   -> block_or_investigate

## Final Validation Status

Ran 80 tests
OK


## Dashboard Project Overview

The dashboard includes a Project Overview page at /project-overview.

This page summarizes the project problem, solution, architecture layers, implemented capabilities, security decisions, current validation status, and future work.

## Dashboard Authentication

Dashboard authentication is optional and disabled by default for local academic testing.

Enable authentication with these environment variables:

export PROCSENTINEL_DASHBOARD_AUTH_ENABLED=true
export PROCSENTINEL_DASHBOARD_TOKEN=procsentinel-demo-token
python scripts/run_dashboard.py

Authenticated access example:

http://SERVER_IP:8010/project-overview?token=procsentinel-demo-token

Header-based access example:

X-ProcSentinel-Token: procsentinel-demo-token

When authentication is disabled, the dashboard remains open for local academic testing and demonstration.


## Workspace Isolation and Path Enforcement

ProcSentinel AI includes a Workspace Isolation layer that classifies target paths as inside workspace, outside workspace, sensitive path, or critical path.

Demo command:

python scripts/procsentinel_workspace_demo.py

Documentation:

docs/PROCSENTINEL_WORKSPACE_ISOLATION.md
