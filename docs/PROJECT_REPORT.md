AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

INITIAL PROJECT REPORT

1. PROJECT OVERVIEW

This project implements a Linux behavioral security system that executes processes through a controlled sandbox pipeline, monitors runtime behavior, extracts behavioral features, applies rule-based detection, and generates a final risk score.

The project focuses on behavioral analysis instead of static malware signatures. The system evaluates what a process does during execution.

2. PROBLEM STATEMENT

Linux systems may execute scripts and commands from different sources. Running untrusted commands directly can cause security and stability problems such as deleting files, consuming excessive resources, running for too long, or behaving abnormally.

The project solves this by creating a controlled execution and monitoring pipeline.

3. PROJECT OBJECTIVES

The project objectives are:

- Run Linux processes through a controlled runner.
- Apply command execution policy before execution.
- Enforce timeout, CPU, memory, and open files limits.
- Monitor runtime process behavior.
- Store process monitoring samples.
- Generate process sample summaries.
- Extract behavioral features.
- Apply rule-based detection.
- Produce risk score, risk level, triggered rules, and security explanation.
- Prepare clear demo scenarios for presentation.

4. SYSTEM PIPELINE

The current system pipeline is:

Command Input
→ Sandbox Runner
→ Command Policy
→ Resource Limits
→ Process Monitoring
→ Sample Summary
→ Behavioral Feature Extraction
→ Rule-Based Detection
→ Risk Score
→ Demo Output

5. CORE COMPONENTS

Sandbox Runner:
Located at app/sandbox/runner.py

Responsibilities:
- Execute commands.
- Capture stdout and stderr.
- Capture exit code.
- Apply timeout.
- Apply resource limits.
- Start process monitoring.
- Store sandbox run metadata.

Command Policy:
Located at app/sandbox/policy.py

Responsibilities:
- Block dangerous commands.
- Allow controlled commands.
- Prevent unsafe Python execution modes.

Examples of blocked commands:
rm, dd, mkfs, shutdown, reboot, sudo, bash, curl, wget

Examples of blocked Python modes:
python -c
python -m

Process Monitoring Engine:
Located at app/monitoring/process_monitor.py

Collected fields:
pid, process name, status, cpu_percent, memory_rss_mb, memory_vms_mb, threads_count, children_count, open_files_count, alive, error, timestamp

Process Sample Summarizer:
Located at app/monitoring/sample_summary.py

Generated summary fields:
samples_count, max_cpu_percent, avg_cpu_percent, max_memory_rss_mb, avg_memory_rss_mb, max_open_files_count, observed_statuses, errors_count, had_errors, last_sample_alive

Behavioral Feature Extractor:
Located at app/features/extractor.py

Generated features:
memory_rss_to_limit_ratio, memory_vms_to_limit_ratio, open_files_to_limit_ratio, blocked_by_policy, timed_out, non_zero_exit, abnormal_termination

Rule-Based Detection Engine:
Located at app/detection/rules.py

Generated output:
risk_score, risk_level, triggered_rules_count, triggered_rules, security_explanation

6. CURRENT DETECTION RULES

The current rule-based engine supports:

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

7. RISK LEVEL SCALE

0 - 29: low
30 - 69: suspicious
70 - 100: high

8. DEMO SCENARIOS

The current demo contains three scenarios.

Safe Process:
Internal command:
python scripts/demo_monitored_process.py

Expected result:
status = completed
risk_score = 0
risk_level = low
triggered_rules_count = 0

Timeout Process:
Internal command:
sleep 5

Expected result:
status = timed_out
risk_score = 35
risk_level = suspicious
triggered_rule = PROCESS_TIMEOUT

Blocked Dangerous Command:
Internal command:
rm -rf /tmp/ai-sandbox-demo-blocked

Expected result:
status = blocked
risk_score = 70
risk_level = high
triggered_rule = POLICY_BLOCKED_COMMAND

9. OUTPUT FILES

The system generates structured JSONL files:

data/raw/sandbox_runs.jsonl
data/raw/process_samples.jsonl
data/processed/process_sample_summaries.jsonl
data/processed/behavioral_features.jsonl
data/processed/detection_results.jsonl
data/processed/demo_results.jsonl

10. TESTING STATUS

The project currently has 62 automated tests.

Validation command:
python -m unittest discover -s tests -p "test_*.py"

Expected result:
Ran 62 tests
OK

The test suite validates:

- Sandbox runner.
- Command policy.
- Resource limits.
- Process monitoring.
- Monitoring summaries.
- Feature extraction.
- Behavioral pipeline.
- Rule-based detection.
- Detection pipeline.
- Demo scenarios.

11. COMPLETED PHASES

Completed phases:

Phase 1: Environment setup
Phase 2: Architecture documentation
Phase 3: Sandbox runner
Phase 4: Process monitoring engine
Phase 5: Behavioral feature extraction
Phase 6: Rule-based detection engine
Phase 7: Demo scenario runner
Phase 8A: Demo guide documentation

12. CURRENT STRENGTHS

The current implementation has:

- Clean Git history.
- Modular architecture.
- Full pipeline from command execution to detection result.
- Clear risk scoring.
- Structured JSONL outputs.
- Automated demo scenarios.
- 36 passing tests.
- A strong foundation for future machine-learning-assisted anomaly scoring.

13. CURRENT LIMITATIONS

The current version does not yet include:

- strace syscall tracing.
- Linux namespaces isolation.
- cgroups integration.
- seccomp profile.
- SQLite or PostgreSQL storage.
- FastAPI backend.
- Monitoring Interface.
- AI anomaly detection model.

These are planned extensions, not failures in the current implementation.

14. NEXT DEVELOPMENT PHASE

The recommended next technical phase is syscall tracing using strace.

This will allow the system to observe file operations, process-related syscalls, and runtime behavior at a lower level.

15. CONCLUSION

The project has reached a working academic prototype. It can execute Linux processes through a controlled pipeline, monitor runtime behavior, extract behavioral features, apply rule-based detection, and produce a clear security risk score.

The main value of the project is its behavioral approach. It evaluates what a process does during execution instead of relying only on static signatures.

16. TRACE-AWARE PIPELINE UPDATE

The project now includes a trace-aware detection pipeline using strace.

This pipeline connects runtime process monitoring with syscall-level tracing. It allows the system to observe file-related syscalls, process-related syscalls, and network-related syscalls.

The new trace-aware pipeline is implemented in:

scripts/run_trace_aware_pipeline.py

The pipeline performs:

- Command policy validation.
- strace-based syscall tracing.
- Process monitoring.
- Sandbox run metadata storage.
- Process sample summarization.
- Syscall event parsing.
- Syscall summary generation.
- Behavioral feature extraction.
- Rule-based detection.

New syscall-level features include:

- total_syscalls
- file_syscalls_count
- process_syscalls_count
- network_syscalls_count
- failed_syscalls_count
- unique_paths_count
- sensitive_paths_count
- execve_count
- openat_count
- connect_count
- has_network_activity
- accessed_sensitive_paths

The rule-based detection engine now includes syscall-based rules:

- SENSITIVE_PATH_ACCESS
- NETWORK_ACTIVITY_OBSERVED
- FAILED_SYSCALL_ACTIVITY

The failed syscall threshold was calibrated to reduce false positives caused by normal Linux loader behavior during Python execution.

Current validation status:

58 automated tests
OK

The project has now moved from general process monitoring to system-level behavioral analysis.

17. FINAL THREE-LAYER ARCHITECTURE

The final version of the project is implemented as a three-layer system.

Layer 1: Systems Layer

This layer performs controlled Linux process execution and low-level runtime observation.

It includes:

- Controlled process execution.
- Runtime resource limits.
- Timeout enforcement.
- Process monitoring using psutil.
- strace syscall tracing.
- Runtime JSONL data collection.

Layer 2: Cybersecurity Layer

This layer analyzes the collected behavior and applies security decision logic.

It includes:

- Command execution policy.
- Dangerous command blocking.
- Rule-based detection.
- Sensitive filesystem path detection.
- Network syscall activity detection.
- Failed syscall activity detection.
- Cybersecurity risk score.
- Cybersecurity risk level.
- Human-readable security explanation.

Layer 3: AI Layer

This layer applies machine learning-based anomaly detection on behavioral features.

It includes:

- Behavioral feature vector generation.
- IsolationForest model training.
- AI inference.
- AI anomaly score.
- AI prediction.
- AI risk level.
- AI explanation.

The AI layer is implemented in:

app/ai/anomaly_detector.py

The AI scripts are:

scripts/train_ai_model.py
scripts/run_ai_inference.py

18. FINAL UNIFIED DEMO

The final unified demo is implemented in:

scripts/run_final_demo.py

The final demo produces:

- systems_status
- total_syscalls
- cybersecurity_risk_score
- cybersecurity_risk_level
- cybersecurity_triggered_rules
- ai_anomaly_score
- ai_prediction
- ai_risk_level
- ai_explanation
- final_decision

The final decisions are:

- allow
- review
- block_or_investigate

Final validation status:

62 automated tests
OK

The project now satisfies the required three-layer design:

Systems Layer
Cybersecurity Layer
AI Layer
