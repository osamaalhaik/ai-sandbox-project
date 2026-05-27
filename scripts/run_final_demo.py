import argparse
import json
import shutil
import sys
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


DATA_FILES = [
    ROOT_DIR / "data/raw/sandbox_runs.jsonl",
    ROOT_DIR / "data/raw/process_samples.jsonl",
    ROOT_DIR / "data/raw/syscall_events.jsonl",
    ROOT_DIR / "data/raw/trace_aware_runs.jsonl",
    ROOT_DIR / "data/processed/process_sample_summaries.jsonl",
    ROOT_DIR / "data/processed/syscall_summaries.jsonl",
    ROOT_DIR / "data/processed/behavioral_features.jsonl",
    ROOT_DIR / "data/processed/detection_results.jsonl",
    ROOT_DIR / "data/processed/ai_inference_results.jsonl",
    ROOT_DIR / "data/processed/final_demo_results.jsonl",
]


SCENARIOS = {
    "safe": {
        "title": "Safe trace-aware Python process",
        "command": ["python", "scripts/demo_safe_process.py"],
        "expected_risk_score": 0,
        "expected_risk_level": "low",
    },
    "sensitive": {
        "title": "Sensitive path access detected by strace",
        "command": ["python", "scripts/demo_sensitive_path_access.py"],
        "expected_risk_score": 45,
        "expected_risk_level": "suspicious",
    },
    "blocked": {
        "title": "Dangerous command blocked by policy",
        "command": ["rm", "-rf", "/tmp/final-demo-blocked-test"],
        "expected_risk_score": 70,
        "expected_risk_level": "high",
    },
}


def reset_data_files():
    for path in DATA_FILES:
        if path.exists():
            path.unlink()

    trace_dir = ROOT_DIR / "data/raw/strace"

    if trace_dir.exists():
        shutil.rmtree(trace_dir)


def selected_scenarios(name):
    if name == "all":
        return ["safe", "sensitive", "blocked"]

    if name not in SCENARIOS:
        raise SystemExit("Unknown scenario")

    return [name]


def rule_ids(detection):
    return [item.rule_id for item in detection.triggered_rules]


def final_decision(detection, ai_result):
    if detection.risk_level == "high" or ai_result.ai_risk_level == "high":
        return "block_or_investigate"

    if detection.risk_level == "suspicious" or ai_result.ai_risk_level == "suspicious":
        return "review"

    return "allow"


def run_scenario(scenario_id, ai_detector):
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
    ai_result = ai_detector.infer_by_run_id(run_record["run_id"])

    record = {
        "scenario_id": scenario_id,
        "title": scenario["title"],
        "run_id": run_record["run_id"],
        "command": scenario["command"],
        "systems_status": run_record["status"],
        "total_syscalls": syscall_summary.total_syscalls,
        "file_syscalls_count": syscall_summary.file_syscalls_count,
        "process_syscalls_count": syscall_summary.process_syscalls_count,
        "network_syscalls_count": syscall_summary.network_syscalls_count,
        "sensitive_paths_count": syscall_summary.sensitive_paths_count,
        "accessed_sensitive_paths": features.accessed_sensitive_paths,
        "cybersecurity_risk_score": detection.risk_score,
        "cybersecurity_risk_level": detection.risk_level,
        "cybersecurity_triggered_rules_count": detection.triggered_rules_count,
        "cybersecurity_triggered_rules": rule_ids(detection),
        "ai_anomaly_score": ai_result.ai_anomaly_score,
        "ai_prediction": ai_result.ai_prediction,
        "ai_risk_level": ai_result.ai_risk_level,
        "ai_explanation": ai_result.ai_explanation,
        "final_decision": final_decision(detection, ai_result),
        "expected_risk_score": scenario["expected_risk_score"],
        "expected_risk_level": scenario["expected_risk_level"],
        "passed": detection.risk_score == scenario["expected_risk_score"] and detection.risk_level == scenario["expected_risk_level"],
    }

    write_jsonl(ROOT_DIR / "data/processed/final_demo_results.jsonl", record)
    return record


def write_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["all", "safe", "sensitive", "blocked"], default="all")
    parser.add_argument("--reset-data", action="store_true")
    args = parser.parse_args()

    if args.reset_data:
        reset_data_files()

    ai_detector = AIAnomalyDetector()
    ai_detector.train()

    results = []

    for scenario_id in selected_scenarios(args.scenario):
        results.append(run_scenario(scenario_id, ai_detector))

    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
