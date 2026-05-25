import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class DetectionRuleFinding:
    rule_id: str
    title: str
    severity: str
    score: int
    description: str


@dataclass
class DetectionResult:
    run_id: str
    command_hash: str
    executable: str | None
    status: str
    risk_score: int
    risk_level: str
    triggered_rules_count: int
    triggered_rules: list[DetectionRuleFinding]
    security_explanation: str
    detected_at: str


class RuleBasedDetector:
    def __init__(
        self,
        features_path: str = "data/processed/behavioral_features.jsonl",
        output_path: str = "data/processed/detection_results.jsonl",
    ):
        self.features_path = Path(features_path)
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def detect_latest(self, persist: bool = True) -> DetectionResult:
        features = self._read_latest_record(self.features_path)
        result = self.detect_from_features(features)

        if persist:
            self._store_result(result)

        return result

    def detect_by_run_id(self, run_id: str, persist: bool = True) -> DetectionResult:
        features = self._find_record_by_run_id(self.features_path, run_id)

        if features is None:
            raise ValueError("features_not_found")

        result = self.detect_from_features(features)

        if persist:
            self._store_result(result)

        return result

    def detect_from_features(self, features: dict) -> DetectionResult:
        findings = []

        if bool(features.get("blocked_by_policy")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="POLICY_BLOCKED_COMMAND",
                    title="Command blocked by execution policy",
                    severity="high",
                    score=70,
                    description="The command was blocked before execution because it violated the sandbox command policy.",
                )
            )

        if bool(features.get("timed_out")) or bool(features.get("killed_by_timeout")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="PROCESS_TIMEOUT",
                    title="Process exceeded execution timeout",
                    severity="medium",
                    score=35,
                    description="The process exceeded the allowed execution time and was terminated by the sandbox.",
                )
            )

        if bool(features.get("non_zero_exit")) and not bool(features.get("timed_out")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="NON_ZERO_EXIT",
                    title="Process exited with non-zero status",
                    severity="low",
                    score=15,
                    description="The process returned a non-zero exit code, which may indicate abnormal behavior or execution failure.",
                )
            )

        memory_rss_ratio = float(features.get("memory_rss_to_limit_ratio") or 0.0)

        if memory_rss_ratio >= 0.85:
            findings.append(
                DetectionRuleFinding(
                    rule_id="HIGH_RSS_MEMORY_USAGE",
                    title="High resident memory usage",
                    severity="medium",
                    score=30,
                    description="The process used a high percentage of its allowed resident memory limit.",
                )
            )
        elif memory_rss_ratio >= 0.60:
            findings.append(
                DetectionRuleFinding(
                    rule_id="ELEVATED_RSS_MEMORY_USAGE",
                    title="Elevated resident memory usage",
                    severity="low",
                    score=15,
                    description="The process used a noticeable percentage of its allowed resident memory limit.",
                )
            )

        memory_vms_ratio = float(features.get("memory_vms_to_limit_ratio") or 0.0)

        if memory_vms_ratio >= 1.0:
            findings.append(
                DetectionRuleFinding(
                    rule_id="VIRTUAL_MEMORY_LIMIT_PRESSURE",
                    title="Virtual memory reached configured limit",
                    severity="medium",
                    score=25,
                    description="The process virtual memory usage reached or exceeded the configured memory limit ratio.",
                )
            )

        open_files_ratio = float(features.get("open_files_to_limit_ratio") or 0.0)

        if open_files_ratio >= 0.80:
            findings.append(
                DetectionRuleFinding(
                    rule_id="HIGH_OPEN_FILES_USAGE",
                    title="High open files usage",
                    severity="medium",
                    score=30,
                    description="The process opened a high percentage of the allowed file descriptor limit.",
                )
            )
        elif open_files_ratio >= 0.50:
            findings.append(
                DetectionRuleFinding(
                    rule_id="ELEVATED_OPEN_FILES_USAGE",
                    title="Elevated open files usage",
                    severity="low",
                    score=15,
                    description="The process opened a noticeable percentage of the allowed file descriptor limit.",
                )
            )

        max_children_count = int(features.get("max_children_count") or 0)

        if max_children_count >= 5:
            findings.append(
                DetectionRuleFinding(
                    rule_id="HIGH_CHILD_PROCESS_COUNT",
                    title="High child process creation",
                    severity="medium",
                    score=30,
                    description="The process created multiple child processes, which may indicate process spawning behavior.",
                )
            )
        elif max_children_count >= 1:
            findings.append(
                DetectionRuleFinding(
                    rule_id="CHILD_PROCESS_CREATED",
                    title="Child process observed",
                    severity="low",
                    score=10,
                    description="The process created at least one child process during execution.",
                )
            )

        if bool(features.get("had_monitoring_errors")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="MONITORING_ERRORS_OBSERVED",
                    title="Monitoring errors observed",
                    severity="low",
                    score=10,
                    description="The monitoring engine observed runtime errors while collecting process samples.",
                )
            )

        if bool(features.get("accessed_sensitive_paths")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="SENSITIVE_PATH_ACCESS",
                    title="Sensitive filesystem path accessed",
                    severity="medium",
                    score=45,
                    description="The traced syscall behavior shows access to sensitive filesystem paths such as credential, system, or privileged configuration files.",
                )
            )

        if bool(features.get("has_network_activity")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="NETWORK_ACTIVITY_OBSERVED",
                    title="Network syscall activity observed",
                    severity="low",
                    score=20,
                    description="The traced syscall behavior includes network-related system calls such as connect, socket, send, or receive operations.",
                )
            )

        failed_syscalls_count = int(features.get("failed_syscalls_count") or 0)

        if failed_syscalls_count >= 10:
            findings.append(
                DetectionRuleFinding(
                    rule_id="FAILED_SYSCALL_ACTIVITY",
                    title="Repeated failed syscalls observed",
                    severity="low",
                    score=15,
                    description="The traced syscall behavior includes repeated failed system calls, which may indicate probing, permission issues, or abnormal runtime behavior.",
                )
            )

        samples_count = int(features.get("samples_count") or 0)

        if bool(features.get("policy_allowed")) and samples_count == 0 and not bool(features.get("blocked_by_policy")):
            findings.append(
                DetectionRuleFinding(
                    rule_id="NO_RUNTIME_SAMPLES",
                    title="No runtime samples collected",
                    severity="low",
                    score=10,
                    description="The process was allowed to run but no runtime monitoring samples were collected.",
                )
            )

        risk_score = min(100, sum(item.score for item in findings))
        risk_level = self._risk_level(risk_score)
        explanation = self._build_explanation(risk_score, risk_level, findings)

        return DetectionResult(
            run_id=str(features.get("run_id")),
            command_hash=str(features.get("command_hash") or ""),
            executable=features.get("executable"),
            status=str(features.get("status") or "unknown"),
            risk_score=risk_score,
            risk_level=risk_level,
            triggered_rules_count=len(findings),
            triggered_rules=findings,
            security_explanation=explanation,
            detected_at=datetime.now(timezone.utc).isoformat(),
        )

    def _risk_level(self, risk_score: int) -> str:
        if risk_score >= 70:
            return "high"

        if risk_score >= 30:
            return "suspicious"

        return "low"

    def _build_explanation(
        self,
        risk_score: int,
        risk_level: str,
        findings: list[DetectionRuleFinding],
    ) -> str:
        if not findings:
            return "No suspicious behavior was detected by the rule-based engine."

        titles = ", ".join(item.title for item in findings)

        return f"Risk level is {risk_level} with score {risk_score}. Triggered rules: {titles}."

    def _read_latest_record(self, path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(str(path))

        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

        if not lines:
            raise ValueError("no_records_found")

        return json.loads(lines[-1])

    def _find_record_by_run_id(self, path: Path, run_id: str) -> dict | None:
        if not path.exists():
            return None

        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            record = json.loads(line)

            if record.get("run_id") == run_id:
                return record

        return None

    def _store_result(self, result: DetectionResult) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
