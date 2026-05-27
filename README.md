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

Ran 58 tests
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

The current version is a working academic prototype with a full trace-aware behavioral detection pipeline and 58 passing automated tests.

## Next Planned Work

- Improve trace-aware demo scenarios
- Add syscall-based demo case for sensitive path access
- Add SQLite persistence
- Add FastAPI backend
- Add dashboard
- Add AI anomaly detection layer
- Add stronger Linux isolation using namespaces, cgroups, and seccomp

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
