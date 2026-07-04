# Project Status Snapshot

## Project Name

AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

## Current Status

The project is a working academic prototype with a full trace-aware behavioral detection pipeline.

## Current Validation

58 automated tests are passing.

Validation command:

    python -m unittest discover -s tests -p "test_*.py"

Expected result:

    Ran 72 tests
    OK

## Completed Core Capabilities

- Project structure and environment setup
- Architecture documentation
- Sandbox process runner
- Command execution policy
- Runtime resource limits
- Process monitoring engine
- Process sample summarization
- Behavioral feature extraction
- Rule-based detection engine
- Demo scenarios
- strace syscall tracing
- strace parser
- Syscall summary engine
- Syscall-based behavioral features
- Syscall-based detection rules
- Trace-aware detection pipeline
- Final demo checklist
- Updated README
- Initial project report

## Current Main Pipeline

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

## Main Working Commands

Run all tests:

    python -m unittest discover -s tests -p "test_*.py"

Run basic demo scenarios:

    python scripts/run_demo_scenarios.py --scenario all

Run trace-aware safe process:

    python scripts/run_trace_aware_pipeline.py --monitor-interval 0.1 -- python scripts/demo_safe_process.py

Run trace-aware blocked command:

    python scripts/run_trace_aware_pipeline.py -- rm -rf /tmp/trace-aware-blocked-test

## Expected Demo Results

Basic demo:

    safe process = low risk
    timeout process = suspicious risk
    blocked command = high risk

Trace-aware demo:

    safe process = risk_score 0
    blocked command = risk_score 70

## Current Detection Rules

- POLICY_BLOCKED_COMMAND
- PROCESS_TIMEOUT
- NON_ZERO_EXIT
- HIGH_RSS_MEMORY_USAGE
- ELEVATED_RSS_MEMORY_USAGE
- VIRTUAL_MEMORY_LIMIT_PRESSURE
- HIGH_OPEN_FILES_USAGE
- ELEVATED_OPEN_FILES_USAGE
- HIGH_CHILD_PROCESS_COUNT
- CHILD_PROCESS_CREATED
- MONITORING_ERRORS_OBSERVED
- NO_RUNTIME_SAMPLES
- SENSITIVE_PATH_ACCESS
- NETWORK_ACTIVITY_OBSERVED
- FAILED_SYSCALL_ACTIVITY

## Current Documentation Files

- README.md
- docs/ARCHITECTURE.md
- docs/COMPONENTS.md
- docs/ROADMAP.md
- docs/DEMO_GUIDE.md
- docs/PROJECT_REPORT.md
- docs/FINAL_DEMO_CHECKLIST.md

## Current Test Coverage Areas

- Sandbox runner
- Command policy
- Resource limits
- Process monitoring
- Monitoring integration
- Sample summaries
- Behavioral feature extraction
- Behavioral pipeline
- Rule-based detection
- Detection pipeline
- Demo scenarios
- strace parser
- Syscall summary
- Syscall feature extraction
- Syscall detection rules
- Trace-aware pipeline

## Remaining Work Before Academic Submission

- Add a final sensitive-path trace demo scenario
- Add final presentation script
- Update report with screenshots or copied terminal outputs
- Prepare final ZIP or repository submission
- Optional: generate PDF report

## Remaining Work For Product-Level Version

- Production-grade PostgreSQL persistence and long-term retention
- API hardening and authentication
- Production-grade authenticated monitoring interface
- Dashboard authentication and role-based access control
- AI anomaly detection model improvement and larger dataset evaluation
- Stronger Linux namespace isolation
- Stronger cgroups enforcement
- seccomp syscall filtering
- service deployment
- production-grade audit log retention and export
- packaging and installer

## Technical Assessment

The current project is strong enough for a university systems project demonstration. It has a real Linux process execution pipeline, resource control, process monitoring, syscall tracing, feature extraction, and rule-based behavioral threat detection.

The project is not yet a production security product, but it is a strong academic prototype and a solid foundation for further development.

## Final Unified Demo Status

The project now includes a final unified demo runner:

    scripts/run_final_demo.py

Main command:

    python scripts/run_final_demo.py --scenario all --reset-data

The final demo includes:

    safe trace-aware process
    sensitive path access detected through strace
    dangerous command blocked by policy

Expected results:

    safe = low risk
    sensitive = suspicious risk
    blocked = high risk
