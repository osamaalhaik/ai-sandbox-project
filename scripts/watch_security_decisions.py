import json
import time
from pathlib import Path

DETECTION_PATH = Path("data/processed/detection_results.jsonl")

def decision_for(record):
    risk_level = record.get("risk_level")

    if risk_level == "low":
        return "allow"

    if risk_level == "suspicious":
        return "review"

    return "block_or_investigate"

def rule_ids(record):
    rules = record.get("triggered_rules", [])
    result = []

    for rule in rules:
        if isinstance(rule, dict):
            result.append(rule.get("rule_id", "UNKNOWN_RULE"))
        else:
            result.append(str(rule))

    return result

def main():
    DETECTION_PATH.parent.mkdir(parents=True, exist_ok=True)
    DETECTION_PATH.touch()

    print("SECURITY_DECISION_WATCHER_STARTED")
    print("watching=data/processed/detection_results.jsonl")
    print("waiting_for_real_commands=true")
    print("-" * 70, flush=True)

    with DETECTION_PATH.open("r", encoding="utf-8") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.2)
                continue

            record = json.loads(line)

            print("NEW_SECURITY_DECISION")
            print("Run ID:", record.get("run_id"))
            print("Executable:", record.get("executable"))
            print("Status:", record.get("status"))
            print("Risk Score:", record.get("risk_score"))
            print("Risk Level:", record.get("risk_level"))
            print("Triggered Rules:", rule_ids(record))
            print("Decision:", decision_for(record))
            print("Explanation:", record.get("security_explanation"))
            print("-" * 70, flush=True)

if __name__ == "__main__":
    main()
