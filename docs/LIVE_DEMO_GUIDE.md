# Live Demo Guide

## Project

AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

## Demo Idea

This live demo shows the project as a running behavioral security monitor.

The system runs in one terminal and waits for incoming analysis requests.  
A second terminal sends different scenarios.  
The first terminal analyzes each scenario through the full pipeline and prints the final security decision.

## Why This Demo Matches the Project

The project is designed to monitor Linux process behavior, detect suspicious runtime activity, and produce a final decision.

This demo proves that the system can:

- receive an input request
- run the selected process inside the trace-aware pipeline
- apply command policy
- monitor runtime process behavior
- trace system calls using strace
- extract behavioral features
- apply cybersecurity detection rules
- calculate AI anomaly score
- produce a final decision

## Terminal 1: Start the Live Monitor

Run:

    cd ~/ai-sandbox-project
    source venv/bin/activate
    python scripts/run_live_monitor.py

Expected startup output:

    LIVE_MONITOR_STARTED
    waiting_for_requests=true

This terminal should stay open.

## Terminal 2: Send Live Inputs

Open a second terminal and run:

    cd ~/ai-sandbox-project
    source venv/bin/activate

Send a safe process:

    python scripts/send_live_input.py --scenario safe

Send a sensitive path access scenario:

    python scripts/send_live_input.py --scenario sensitive

Send a blocked dangerous command scenario:

    python scripts/send_live_input.py --scenario blocked

## Expected Results in Terminal 1

Safe scenario:

    scenario_id = safe
    cybersecurity_risk_score = 0
    cybersecurity_risk_level = low
    final_decision = allow
    passed = true

Sensitive scenario:

    scenario_id = sensitive
    sensitive_paths_count = 1
    accessed_sensitive_paths = true
    cybersecurity_triggered_rules = SENSITIVE_PATH_ACCESS
    final_decision = review
    passed = true

Blocked scenario:

    scenario_id = blocked
    systems_status = blocked
    cybersecurity_triggered_rules = POLICY_BLOCKED_COMMAND
    final_decision = block_or_investigate
    passed = true

## Evidence for Sensitive Path Access

After running the sensitive scenario, run:

    grep -n "/etc/passwd" data/raw/syscall_events.jsonl | head

Expected evidence:

    openat(... "/etc/passwd" ...)

This proves that strace captured a real system call accessing a sensitive Linux file.

## Final Explanation for the Instructor

This demo shows the system working as a live behavioral threat monitor.

Terminal 1 represents the running security monitor.  
Terminal 2 represents incoming user or system requests.

Each request is analyzed using:

- command policy
- process monitoring
- strace syscall tracing
- behavioral feature extraction
- rule-based cybersecurity detection
- AI anomaly scoring
- final decision logic

The final decisions are:

    safe      -> allow
    sensitive -> review
    blocked   -> block_or_investigate

## Important Note

The AI layer is used as an assisting anomaly-scoring layer.  
The final security decision prioritizes cybersecurity rules first, then uses AI as supporting evidence.

This avoids false positives where AI alone marks a safe process as suspicious.
