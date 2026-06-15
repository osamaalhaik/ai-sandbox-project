import argparse
import json
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.ai.anomaly_detector import AIAnomalyDetector
from app.detection.rules import RuleBasedDetector
from app.features.extractor import BehavioralFeatureExtractor
from app.monitoring.sample_summary import ProcessSampleSummarizer
from app.tracing.syscall_summary import SyscallSummarizer
from scripts.run_trace_aware_pipeline import run_traced_command


SCENARIOS = {
    "safe": {
        "title": "Safe process",
        "command": ["python", "scripts/demo_safe_process.py"],
        "expected_decision": "allow",
    },
    "sensitive": {
        "title": "Sensitive path access",
        "command": ["python", "scripts/demo_sensitive_path_access.py"],
        "expected_decision": "review",
    },
    "blocked": {
        "title": "Dangerous blocked command",
        "command": ["rm", "-rf", "/tmp/live-monitor-blocked-test"],
        "expected_decision": "block_or_investigate",
    },
}


def write_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def decide(detection, ai_result):
    if detection.risk_level == "high":
        return "block_or_investigate"

    if detection.risk_level == "suspicious":
        return "review"

    if ai_result.ai_risk_level == "high":
        return "review"

    return "allow"


def process_request(request_path):
    request = json.loads(request_path.read_text(encoding="utf-8"))
    scenario_id = request.get("scenario")

    if scenario_id not in SCENARIOS:
        result = {
            "request_file": str(request_path),
            "scenario_id": scenario_id,
            "status": "rejected",
            "reason": "unknown_scenario",
            "allowed_scenarios": sorted(SCENARIOS.keys()),
        }
        write_jsonl(ROOT_DIR / "data/live/results/live_monitor_results.jsonl", result)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
        return result

    scenario = SCENARIOS[scenario_id]

    run_record, trace_record = run_traced_command(
        command=scenario["command"],
        timeout_seconds=10,
        max_cpu_seconds=5,
        max_memory_mb=256,
        max_open_files=64,
        working_directory=str(ROOT_DIR),
        monitor_interval_seconds=0.1,
    )

    process_summary = ProcessSampleSummarizer().summarize(run_record["run_id"])
    syscall_summary = SyscallSummarizer().summarize(run_record["run_id"])
    features = BehavioralFeatureExtractor().extract_by_run_id(run_record["run_id"])
    detection = RuleBasedDetector().detect_by_run_id(run_record["run_id"])

    ai_detector = AIAnomalyDetector()
    ai_detector.train()
    try:
        ai_result = ai_detector.infer_by_run_id(run_record["run_id"])
    except ValueError:
        ai_result = ai_detector.infer_record(asdict(features))

    final_decision = decide(detection, ai_result)

    result = {
        "request_file": str(request_path),
        "scenario_id": scenario_id,
        "title": scenario["title"],
        "run_id": run_record["run_id"],
        "systems_status": run_record["status"],
        "total_syscalls": syscall_summary.total_syscalls,
        "file_syscalls_count": syscall_summary.file_syscalls_count,
        "process_syscalls_count": syscall_summary.process_syscalls_count,
        "network_syscalls_count": syscall_summary.network_syscalls_count,
        "sensitive_paths_count": syscall_summary.sensitive_paths_count,
        "accessed_sensitive_paths": features.accessed_sensitive_paths,
        "cybersecurity_risk_score": detection.risk_score,
        "cybersecurity_risk_level": detection.risk_level,
        "cybersecurity_triggered_rules": [item.rule_id for item in detection.triggered_rules],
        "ai_anomaly_score": ai_result.ai_anomaly_score,
        "ai_prediction": ai_result.ai_prediction,
        "ai_risk_level": ai_result.ai_risk_level,
        "final_decision": final_decision,
        "expected_decision": scenario["expected_decision"],
        "passed": final_decision == scenario["expected_decision"],
    }

    write_jsonl(ROOT_DIR / "data/live/results/live_monitor_results.jsonl", result)

    print("", flush=True)
    print("LIVE_ANALYSIS_RESULT", flush=True)
    print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)

    processed_dir = ROOT_DIR / "data/live/processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(request_path), str(processed_dir / request_path.name))

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--incoming-dir", default="data/live/incoming")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    incoming_dir = ROOT_DIR / args.incoming_dir
    incoming_dir.mkdir(parents=True, exist_ok=True)

    print("LIVE_MONITOR_STARTED", flush=True)
    print(f"incoming_dir={incoming_dir}", flush=True)
    print("waiting_for_requests=true", flush=True)

    seen = set()

    while True:
        request_files = sorted(incoming_dir.glob("*.json"), key=lambda item: (item.stat().st_mtime, item.name))

        for request_path in request_files:
            if request_path in seen:
                continue

            seen.add(request_path)
            process_request(request_path)

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
