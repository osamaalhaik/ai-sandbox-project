import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.detection.rules import RuleBasedDetector
from app.features.extractor import BehavioralFeatureExtractor
from app.monitoring.sample_summary import ProcessSampleSummarizer
from app.sandbox.runner import SandboxRunner


DATA_FILES = [
    ROOT_DIR / "data/raw/sandbox_runs.jsonl",
    ROOT_DIR / "data/raw/process_samples.jsonl",
    ROOT_DIR / "data/processed/process_sample_summaries.jsonl",
    ROOT_DIR / "data/processed/behavioral_features.jsonl",
    ROOT_DIR / "data/processed/detection_results.jsonl",
    ROOT_DIR / "data/processed/demo_results.jsonl",
]


SCENARIOS = {
    "safe": {
        "title": "Safe monitored Python process",
        "command": ["python", "scripts/demo_monitored_process.py"],
        "timeout_seconds": 20,
        "monitor_interval_seconds": 0.1,
    },
    "timeout": {
        "title": "Long-running process terminated by timeout",
        "command": ["sleep", "5"],
        "timeout_seconds": 1,
        "monitor_interval_seconds": 0.1,
    },
    "blocked": {
        "title": "Dangerous command blocked by policy",
        "command": ["rm", "-rf", "/tmp/ai-sandbox-demo-blocked"],
        "timeout_seconds": 10,
        "monitor_interval_seconds": 0.1,
    },
}


def reset_data_files():
    for path in DATA_FILES:
        if path.exists():
            path.unlink()


def run_pipeline(scenario_id, scenario):
    runner = SandboxRunner()
    summarizer = ProcessSampleSummarizer()
    extractor = BehavioralFeatureExtractor()
    detector = RuleBasedDetector()

    run_result = runner.run(
        command=scenario["command"],
        timeout_seconds=scenario["timeout_seconds"],
        working_directory=str(ROOT_DIR),
        monitor_interval_seconds=scenario["monitor_interval_seconds"],
    )

    sample_summary = summarizer.summarize(run_result.run_id)
    features = extractor.extract_by_run_id(run_result.run_id)
    detection_result = detector.detect_by_run_id(run_result.run_id)

    output = {
        "scenario_id": scenario_id,
        "title": scenario["title"],
        "run_id": run_result.run_id,
        "command": scenario["command"],
        "status": run_result.status,
        "samples_count": sample_summary.samples_count,
        "executable": features.executable,
        "risk_score": detection_result.risk_score,
        "risk_level": detection_result.risk_level,
        "triggered_rules_count": detection_result.triggered_rules_count,
        "triggered_rules": [item.rule_id for item in detection_result.triggered_rules],
        "security_explanation": detection_result.security_explanation,
    }

    store_demo_result(output)
    return output


def store_demo_result(result):
    output_path = ROOT_DIR / "data/processed/demo_results.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(result, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["safe", "timeout", "blocked", "all"], default="all")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()

    if args.reset:
        reset_data_files()

    selected = SCENARIOS.keys() if args.scenario == "all" else [args.scenario]
    results = []

    for scenario_id in selected:
        results.append(run_pipeline(scenario_id, SCENARIOS[scenario_id]))

    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
