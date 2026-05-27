# Demo Guide

## Project Name

AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

## Demo Objective

This demo proves that the system can execute Linux processes through a controlled sandbox pipeline, monitor runtime behavior, extract behavioral features, apply rule-based detection, and generate a final security risk score.

## Full Pipeline

The system executes the following pipeline:

1. Run the process through the sandbox runner.
2. Apply command execution policy.
3. Enforce runtime limits.
4. Monitor process behavior.
5. Store runtime samples.
6. Summarize process samples.
7. Extract behavioral features.
8. Apply rule-based detection.
9. Generate risk score, risk level, triggered rules, and explanation.

## Main Demo Command

    python scripts/run_demo_scenarios.py --scenario all

## Pre-Demo Validation Command

    python -m unittest discover -s tests -p "test_*.py"

Expected result:

    Ran 36 tests
    OK

## Scenario 1: Safe Process

### Purpose

This scenario shows a normal Python process that runs safely, consumes limited resources, and finishes without triggering suspicious rules.

### Internal Command

    python scripts/demo_monitored_process.py

### Expected Result

    status = completed
    risk_score = 0
    risk_level = low
    triggered_rules_count = 0

### Security Interpretation

The process completed normally. The sandbox collected monitoring samples, generated a behavioral summary, extracted features, and the detection engine found no suspicious behavior.

## Scenario 2: Timeout Process

### Purpose

This scenario shows a process that exceeds the configured execution timeout.

### Internal Command

    sleep 5

### Expected Result

    status = timed_out
    risk_score = 35
    risk_level = suspicious
    triggered_rules_count = 1
    triggered_rule = PROCESS_TIMEOUT

### Security Interpretation

The process exceeded its allowed execution time and was terminated by the sandbox. This is not automatically malicious, but it is suspicious runtime behavior that should be reported.

## Scenario 3: Blocked Dangerous Command

### Purpose

This scenario proves that the sandbox does not blindly execute dangerous commands.

### Internal Command

    rm -rf /tmp/ai-sandbox-demo-blocked

### Expected Result

    status = blocked
    risk_score = 70
    risk_level = high
    triggered_rules_count = 1
    triggered_rule = POLICY_BLOCKED_COMMAND

### Security Interpretation

The command was blocked before execution because it violated the command execution policy. No process was started, no PID was created, and no runtime samples were generated.

## Generated Output Files

The demo generates the following files:

    data/raw/sandbox_runs.jsonl
    data/raw/process_samples.jsonl
    data/processed/process_sample_summaries.jsonl
    data/processed/behavioral_features.jsonl
    data/processed/detection_results.jsonl
    data/processed/demo_results.jsonl

## Important Sandbox Fields

    run_id
    command
    pid
    status
    policy_allowed
    policy_reason
    timed_out
    killed_by_timeout
    resource_limits

## Important Monitoring Summary Fields

    samples_count
    max_cpu_percent
    avg_cpu_percent
    max_memory_rss_mb
    avg_memory_rss_mb
    max_open_files_count
    observed_statuses
    had_errors

## Important Behavioral Feature Fields

    memory_rss_to_limit_ratio
    memory_vms_to_limit_ratio
    open_files_to_limit_ratio
    blocked_by_policy
    timed_out
    non_zero_exit
    abnormal_termination

## Important Detection Fields

    risk_score
    risk_level
    triggered_rules_count
    triggered_rules
    security_explanation

## Risk Level Scale

    0 - 29    low
    30 - 69   suspicious
    70 - 100  high

## Current Detection Rules

    POLICY_BLOCKED_COMMAND
    PROCESS_TIMEOUT
    NON_ZERO_EXIT
    HIGH_RSS_MEMORY_USAGE
    ELEVATED_RSS_MEMORY_USAGE
    VIRTUAL_MEMORY_LIMIT_PRESSURE
    HIGH_OPEN_FILES_USAGE
    ELEVATED_OPEN_FILES_USAGE
    HIGH_CHILD_PROCESS_COUNT
    CHILD_PROCESS_CREATED
    MONITORING_ERRORS_OBSERVED
    NO_RUNTIME_SAMPLES

## Suggested Live Demo Order

1. Show the project structure.
2. Run the automated test suite.
3. Run all demo scenarios.
4. Explain the safe process result.
5. Explain the timeout process result.
6. Explain the blocked command result.
7. Show the generated JSONL output files.
8. Explain how risk score is calculated.
9. Explain how this prepares the project for the AI layer.

## Live Presentation Commands

    cd ~/ai-sandbox-project
    source venv/bin/activate
    python -m unittest discover -s tests -p "test_*.py"
    python scripts/run_demo_scenarios.py --scenario all
    tail -n 3 data/processed/demo_results.jsonl

## Instructor Explanation

This project does not rely on static malware signatures. It analyzes runtime behavior. Each process is executed through a controlled pipeline, monitored during execution, converted into behavioral features, and evaluated using rule-based detection. The current implementation is ready for a future AI-based anomaly detection layer because it already produces structured behavioral features.

## Trace-Aware Detection Pipeline

The project now includes a trace-aware detection pipeline based on strace.

This pipeline combines:

    command policy
    strace syscall tracing
    process monitoring
    process sample summary
    syscall summary
    behavioral feature extraction
    rule-based detection

## Trace-Aware Pipeline Command

    python scripts/run_trace_aware_pipeline.py --monitor-interval 0.1 -- python scripts/demo_safe_process.py

## Trace-Aware Blocked Command Example

    python scripts/run_trace_aware_pipeline.py -- rm -rf /tmp/trace-aware-blocked-test

## Trace-Aware Safe Process Expected Result

    status = completed
    total_syscalls > 0
    file_syscalls_count > 0
    process_syscalls_count > 0
    failed_syscalls_count is tolerated if below calibrated threshold
    risk_score = 0
    risk_level = low
    triggered_rules_count = 0

## Trace-Aware Blocked Command Expected Result

    status = blocked
    total_syscalls = 0
    risk_score = 70
    risk_level = high
    triggered_rule = POLICY_BLOCKED_COMMAND

## Why This Matters

The system now observes behavior at two levels:

    process-level metrics using psutil
    system-call-level behavior using strace

This makes the project stronger because it can analyze file, process, and network-related system calls instead of relying only on CPU and memory metrics.

## Final Unified Demo Runner

The final demo can be executed with one command:

    python scripts/run_final_demo.py --scenario all --reset-data

This command runs three trace-aware scenarios:

    safe process
    sensitive path access
    blocked dangerous command

Expected results:

    safe process risk_score = 0
    sensitive path access risk_score = 45
    blocked command risk_score = 70

All scenarios should return:

    passed = true
