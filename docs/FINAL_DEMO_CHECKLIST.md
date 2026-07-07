# Final Demo Checklist

## Project

AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

## Goal

This checklist defines the exact live demo flow for presenting the project.

## Before Starting

Run:

    cd ~/ai-sandbox-project
    source venv/bin/activate
    git status
    python -m unittest discover -s tests -p "test_*.py"

Expected:

    nothing to commit, working tree clean
    Ran 76 tests
    OK

## Demo Step 1: Show Project Structure

Run:

    tree -L 3 app scripts tests docs

Explain:

The project is modular. It contains sandbox execution, process monitoring, syscall tracing, feature extraction, detection, tests, scripts, and documentation.

## Demo Step 2: Run Basic Demo Scenarios

Run:

    python scripts/run_demo_scenarios.py --scenario all

Expected:

    safe process risk_score = 0
    timeout process risk_score = 35
    blocked command risk_score = 70

Explain:

This proves the basic behavioral pipeline works for normal, suspicious, and blocked execution cases.

## Demo Step 3: Run Trace-Aware Safe Process

Run:

    python scripts/run_trace_aware_pipeline.py --monitor-interval 0.1 -- python scripts/demo_safe_process.py

Expected:

    status = completed
    total_syscalls > 0
    file_syscalls_count > 0
    process_syscalls_count > 0
    risk_score = 0
    risk_level = low
    triggered_rules_count = 0

Explain:

This proves the system combines process monitoring with strace syscall tracing.

## Demo Step 4: Run Trace-Aware Blocked Command

Run:

    python scripts/run_trace_aware_pipeline.py -- rm -rf /tmp/trace-aware-blocked-test

Expected:

    status = blocked
    policy_allowed = false
    risk_score = 70
    risk_level = high
    triggered_rule = POLICY_BLOCKED_COMMAND

Explain:

The command is blocked before execution by the command policy, so no dangerous process is started.

## Demo Step 5: Show Output Files

Run:

    ls data/raw
    ls data/processed
    tail -n 2 data/processed/detection_results.jsonl

Explain:

The system stores raw execution data, monitoring samples, syscall events, summaries, extracted features, and final detection results.

## Demo Step 6: Explain Risk Score

Risk levels:

    0 - 29    low
    30 - 69   suspicious
    70 - 100  high

Important rules:

    POLICY_BLOCKED_COMMAND
    PROCESS_TIMEOUT
    SENSITIVE_PATH_ACCESS
    NETWORK_ACTIVITY_OBSERVED
    FAILED_SYSCALL_ACTIVITY

## Demo Step 7: Explain Why This Is a Systems Project

The project uses:

    Linux process execution
    resource limits
    process monitoring
    strace syscall tracing
    JSONL event pipelines
    rule-based behavioral detection

## Demo Step 8: Explain Future Work

Next improvements:

    production-grade database persistence and retention
    API authentication and hardening
    dashboard charts and report export
    AI model evaluation with larger datasets
    Linux namespaces
    cgroups
    seccomp

## Final Instructor Explanation

This project analyzes process behavior at runtime. It does not depend only on static signatures. It monitors process-level metrics and syscall-level behavior, converts them into behavioral features, and produces a clear security risk score.

## Recommended Final Demo Command

Run:

    python scripts/run_final_demo.py --scenario all --reset-data

Expected:

    safe risk_score = 0
    sensitive risk_score = 45
    blocked risk_score = 70
    passed = true for all scenarios

Use this command as the main live demo command if presentation time is limited.
