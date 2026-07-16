import argparse
import hashlib
import json
import os
import resource
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.detection.rules import RuleBasedDetector
from app.features.extractor import BehavioralFeatureExtractor
from app.monitoring.process_monitor import ProcessMonitor
from app.monitoring.sample_summary import ProcessSampleSummarizer
from app.sandbox.policy import SandboxCommandPolicy
from app.tracing.strace_parser import StraceParser
from app.tracing.syscall_summary import SyscallSummarizer


def normalize_command(command):
    if command and command[0] == "--":
        return command[1:]
    return command


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def hash_command(command):
    return hashlib.sha256("\0".join(command).encode("utf-8")).hexdigest()


def write_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_resource_limits(timeout_seconds, max_cpu_seconds, max_memory_mb, max_open_files):
    return {
        "timeout_seconds": timeout_seconds,
        "max_cpu_seconds": max_cpu_seconds,
        "max_memory_mb": max_memory_mb,
        "max_open_files": max_open_files,
    }


def build_blocked_run_record(run_id, command, working_directory, policy_reason, policy_decision, limits, started_at, finished_at):
    return {
        "run_id": run_id,
        "command": command,
        "command_hash": hash_command(command),
        "working_directory": working_directory,
        "pid": None,
        "status": "blocked",
        "failure_reason": "blocked_by_policy",
        "policy_allowed": False,
        "policy_reason": policy_reason,
        "security_decision": getattr(policy_decision, "security_decision", None),
        "policy_risk_score": getattr(policy_decision, "risk_score", None),
        "policy_risk_level": getattr(policy_decision, "risk_level", None),
        "execution_strategy": getattr(policy_decision, "execution_strategy", None),
        "requires_confirmation": getattr(policy_decision, "requires_confirmation", False),
        "monitoring_enabled": False,
        "samples_count": 0,
        "samples_output_path": "data/raw/process_samples.jsonl",
        "started_at": started_at,
        "finished_at": finished_at,
        "created_at": started_at,
        "updated_at": finished_at,
        "duration_seconds": 0.0,
        "exit_code": None,
        "timed_out": False,
        "killed_by_timeout": False,
        "stdout": "",
        "stderr": f"blocked_by_policy: {policy_reason}",
        "resource_limits": limits,
        "monitor_root_pid": None,
        "wrapper_pid": None,
        "target_pid": None,
        "monitored_pids": [],
        "max_processes_observed": 0,
    }


def run_traced_command(command, timeout_seconds, max_cpu_seconds, max_memory_mb, max_open_files, working_directory, monitor_interval_seconds):
    run_id = str(uuid.uuid4())
    started_at = utc_now()
    start_time = time.time()
    resolved_working_directory = str(Path(working_directory or ROOT_DIR).resolve())
    limits = build_resource_limits(timeout_seconds, max_cpu_seconds, max_memory_mb, max_open_files)
    runs_path = ROOT_DIR / "data/raw/sandbox_runs.jsonl"
    trace_dir = ROOT_DIR / "data/raw/strace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_log_path = trace_dir / f"{run_id}.log"

    policy = SandboxCommandPolicy()
    policy_decision = policy.validate(command, resolved_working_directory)

    if not policy_decision.allowed:
        finished_at = utc_now()
        run_record = build_blocked_run_record(
            run_id,
            command,
            resolved_working_directory,
            policy_decision.reason,
            policy_decision,
            limits,
            started_at,
            finished_at,
        )
        write_jsonl(runs_path, run_record)
        return run_record, {
            "run_id": run_id,
            "trace_log_path": str(trace_log_path),
            "events_count": 0,
            "unique_syscalls_count": 0,
            "category_counts": {},
        }

    monitor = ProcessMonitor(output_path=str(ROOT_DIR / "data/raw/process_samples.jsonl"))
    stop_monitoring = threading.Event()
    samples_count = 0
    observed_pids: set[int] = set()
    max_processes_observed = 0
    target_pid = None
    stdout = ""
    stderr = ""
    exit_code = None
    timed_out = False
    killed_by_timeout = False
    process = None
    monitor_thread = None

    def limit_resources():
        memory_bytes = max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))

    def collect_samples():
        nonlocal samples_count
        nonlocal max_processes_observed
        nonlocal target_pid

        while not stop_monitoring.is_set():
            sample = monitor.sample_tree(
                run_id=run_id,
                root_pid=process.pid,
                include_root=False,
                wrapper_pid=process.pid,
            )

            samples_count += 1
            observed_pids.update(
                sample.monitored_pids
            )
            max_processes_observed = max(
                max_processes_observed,
                sample.process_count,
            )

            if sample.target_pid is not None:
                target_pid = sample.target_pid

            if (
                not sample.alive
                and process.poll() is not None
            ):
                break

            stop_monitoring.wait(
                monitor_interval_seconds
            )

    strace_command = [
        "strace",
        "-f",
        "-tt",
        "-e",
        "trace=file,process,network",
        "-o",
        str(trace_log_path),
        *command,
    ]

    try:
        process = subprocess.Popen(
            strace_command,
            cwd=resolved_working_directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=limit_resources,
            start_new_session=True,
        )

        monitor_thread = threading.Thread(target=collect_samples, daemon=True)
        monitor_thread.start()

        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            killed_by_timeout = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            exit_code = process.returncode

    finally:
        stop_monitoring.set()

        if monitor_thread is not None:
            monitor_thread.join(timeout=2)

    parser = StraceParser(output_path=str(ROOT_DIR / "data/raw/syscall_events.jsonl"))
    events = parser.parse_file(run_id, str(trace_log_path), persist=True)
    finished_at = utc_now()
    duration_seconds = round(time.time() - start_time, 4)

    if timed_out:
        status = "timed_out"
        failure_reason = "timeout_exceeded"
    elif exit_code == 0:
        status = "completed"
        failure_reason = None
    else:
        status = "failed"
        failure_reason = "process_exited_with_error"

    run_record = {
        "run_id": run_id,
        "command": command,
        "command_hash": hash_command(command),
        "working_directory": resolved_working_directory,
        "pid": process.pid if process else None,
        "status": status,
        "failure_reason": failure_reason,
        "policy_allowed": True,
        "policy_reason": policy_decision.reason,
        "security_decision": getattr(policy_decision, "security_decision", None),
        "policy_risk_score": getattr(policy_decision, "risk_score", None),
        "policy_risk_level": getattr(policy_decision, "risk_level", None),
        "execution_strategy": getattr(policy_decision, "execution_strategy", None),
        "requires_confirmation": getattr(policy_decision, "requires_confirmation", False),
        "monitoring_enabled": True,
        "samples_count": samples_count,
        "samples_output_path": "data/raw/process_samples.jsonl",
        "started_at": started_at,
        "finished_at": finished_at,
        "created_at": started_at,
        "updated_at": finished_at,
        "duration_seconds": duration_seconds,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "killed_by_timeout": killed_by_timeout,
        "stdout": stdout,
        "stderr": stderr,
        "resource_limits": limits,
        "monitor_root_pid": (
            process.pid
            if process is not None
            else None
        ),
        "wrapper_pid": (
            process.pid
            if process is not None
            else None
        ),
        "target_pid": target_pid,
        "monitored_pids": sorted(
            observed_pids
        ),
        "max_processes_observed": (
            max_processes_observed
        ),
    }

    write_jsonl(runs_path, run_record)

    trace_record = {
        "run_id": run_id,
        "trace_log_path": str(trace_log_path),
        "events_count": len(events),
        "unique_syscalls_count": len({event.syscall for event in events}),
        "category_counts": category_counts(events),
        "wrapper_pid": (
            process.pid
            if process is not None
            else None
        ),
        "target_pid": target_pid,
        "monitored_pids": sorted(
            observed_pids
        ),
        "max_processes_observed": (
            max_processes_observed
        ),
    }

    write_jsonl(ROOT_DIR / "data/raw/trace_aware_runs.jsonl", trace_record)

    return run_record, trace_record


def category_counts(events):
    counts = {}

    for event in events:
        counts[event.category] = counts.get(event.category, 0) + 1

    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cpu", type=int, default=5)
    parser.add_argument("--memory", type=int, default=256)
    parser.add_argument("--open-files", type=int, default=64)
    parser.add_argument("--cwd", type=str, default=None)
    parser.add_argument("--monitor-interval", type=float, default=0.2)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = normalize_command(args.command)

    if not command:
        raise SystemExit("Command is required")

    run_record, trace_record = run_traced_command(
        command=command,
        timeout_seconds=args.timeout,
        max_cpu_seconds=args.cpu,
        max_memory_mb=args.memory,
        max_open_files=args.open_files,
        working_directory=args.cwd or str(ROOT_DIR),
        monitor_interval_seconds=args.monitor_interval,
    )

    process_summary = ProcessSampleSummarizer().summarize(run_record["run_id"])
    syscall_summary = SyscallSummarizer().summarize(run_record["run_id"])
    features = BehavioralFeatureExtractor().extract_by_run_id(run_record["run_id"])
    detection = RuleBasedDetector().detect_by_run_id(run_record["run_id"])

    output = {
        "sandbox_run": run_record,
        "trace_run": trace_record,
        "process_summary": asdict(process_summary),
        "syscall_summary": asdict(syscall_summary),
        "behavioral_features": asdict(features),
        "detection_result": asdict(detection),
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
