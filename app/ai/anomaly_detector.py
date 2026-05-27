import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


AI_FEATURE_COLUMNS = [
    "duration_seconds",
    "samples_count",
    "observed_duration_seconds",
    "max_cpu_percent",
    "avg_cpu_percent",
    "max_memory_rss_mb",
    "avg_memory_rss_mb",
    "max_memory_vms_mb",
    "avg_memory_vms_mb",
    "memory_rss_to_limit_ratio",
    "memory_vms_to_limit_ratio",
    "max_threads_count",
    "max_children_count",
    "max_open_files_count",
    "open_files_to_limit_ratio",
    "observed_statuses_count",
    "errors_count",
    "total_syscalls",
    "file_syscalls_count",
    "process_syscalls_count",
    "network_syscalls_count",
    "other_syscalls_count",
    "successful_syscalls_count",
    "failed_syscalls_count",
    "unique_syscalls_count",
    "unique_paths_count",
    "sensitive_paths_count",
    "execve_count",
    "openat_count",
    "access_count",
    "connect_count",
    "blocked_by_policy",
    "timed_out",
    "killed_by_timeout",
    "non_zero_exit",
    "abnormal_termination",
    "had_monitoring_errors",
    "last_sample_alive",
    "has_network_activity",
    "accessed_sensitive_paths",
]


@dataclass
class AITrainingResult:
    model_path: str
    metadata_path: str
    training_records_count: int
    feature_columns_count: int
    trained_at: str


@dataclass
class AIInferenceResult:
    run_id: str
    command_hash: str
    executable: str | None
    ai_anomaly_score: float
    ai_prediction: str
    ai_risk_level: str
    ai_explanation: str
    model_path: str
    inferred_at: str


class AIAnomalyDetector:
    def __init__(
        self,
        model_path: str = "data/models/ai_anomaly_model.joblib",
        metadata_path: str = "data/models/ai_anomaly_metadata.json",
        features_path: str = "data/processed/behavioral_features.jsonl",
        output_path: str = "data/processed/ai_inference_results.jsonl",
    ):
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.features_path = Path(features_path)
        self.output_path = Path(output_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def train(self, features_path: str | None = None) -> AITrainingResult:
        records = self.load_feature_records(Path(features_path) if features_path else self.features_path)

        if len(records) < 6:
            records = self.bootstrap_training_records(records)

        matrix = self.records_to_matrix(records)

        model = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "isolation_forest",
                    IsolationForest(
                        n_estimators=200,
                        contamination=0.15,
                        random_state=42,
                    ),
                ),
            ]
        )

        model.fit(matrix)

        joblib.dump(model, self.model_path)

        metadata = {
            "feature_columns": AI_FEATURE_COLUMNS,
            "training_records_count": len(records),
            "feature_columns_count": len(AI_FEATURE_COLUMNS),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "model_type": "IsolationForest",
        }

        self.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        return AITrainingResult(
            model_path=str(self.model_path),
            metadata_path=str(self.metadata_path),
            training_records_count=len(records),
            feature_columns_count=len(AI_FEATURE_COLUMNS),
            trained_at=metadata["trained_at"],
        )

    def infer_latest(self, persist: bool = True) -> AIInferenceResult:
        record = self.read_latest_record(self.features_path)
        return self.infer_record(record, persist=persist)

    def infer_by_run_id(self, run_id: str, persist: bool = True) -> AIInferenceResult:
        record = self.find_record_by_run_id(self.features_path, run_id)

        if record is None:
            raise ValueError("feature_record_not_found")

        return self.infer_record(record, persist=persist)

    def infer_record(self, record: dict, persist: bool = True) -> AIInferenceResult:
        model = self.load_model()
        matrix = self.records_to_matrix([record])
        raw_score = float(model.decision_function(matrix)[0])
        prediction_value = int(model.predict(matrix)[0])
        anomaly_score = self.normalize_score(raw_score, record)
        ai_prediction = "anomaly" if prediction_value == -1 or anomaly_score >= 60 else "normal"
        ai_risk_level = self.risk_level(anomaly_score)
        explanation = self.explain(record, anomaly_score, ai_prediction)

        result = AIInferenceResult(
            run_id=str(record.get("run_id") or ""),
            command_hash=str(record.get("command_hash") or ""),
            executable=record.get("executable"),
            ai_anomaly_score=anomaly_score,
            ai_prediction=ai_prediction,
            ai_risk_level=ai_risk_level,
            ai_explanation=explanation,
            model_path=str(self.model_path),
            inferred_at=datetime.now(timezone.utc).isoformat(),
        )

        if persist:
            self.store_result(result)

        return result

    def load_model(self):
        if not self.model_path.exists():
            self.train()

        return joblib.load(self.model_path)

    def load_feature_records(self, path: Path) -> list[dict]:
        if not path.exists():
            return []

        records = []

        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))

        return records

    def read_latest_record(self, path: Path) -> dict:
        records = self.load_feature_records(path)

        if not records:
            raise ValueError("no_feature_records_found")

        return records[-1]

    def find_record_by_run_id(self, path: Path, run_id: str) -> dict | None:
        for record in self.load_feature_records(path):
            if record.get("run_id") == run_id:
                return record

        return None

    def records_to_matrix(self, records: list[dict]) -> np.ndarray:
        rows = []

        for record in records:
            rows.append([self.numeric_value(record.get(column)) for column in AI_FEATURE_COLUMNS])

        return np.array(rows, dtype=float)

    def numeric_value(self, value) -> float:
        if isinstance(value, bool):
            return 1.0 if value else 0.0

        if value is None:
            return 0.0

        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def normalize_score(self, raw_score: float, record: dict) -> float:
        base = max(0.0, min(100.0, (0.2 - raw_score) * 180.0))
        rule_pressure = 0.0

        if record.get("blocked_by_policy"):
            rule_pressure += 35.0

        if record.get("timed_out"):
            rule_pressure += 25.0

        if record.get("accessed_sensitive_paths"):
            rule_pressure += 35.0

        if record.get("has_network_activity"):
            rule_pressure += 15.0

        if float(record.get("failed_syscalls_count") or 0.0) >= 50:
            rule_pressure += 15.0

        if float(record.get("memory_rss_to_limit_ratio") or 0.0) >= 0.85:
            rule_pressure += 20.0

        return round(max(base, rule_pressure), 4)

    def risk_level(self, score: float) -> str:
        if score >= 70:
            return "high"

        if score >= 30:
            return "suspicious"

        return "low"

    def explain(self, record: dict, score: float, prediction: str) -> str:
        reasons = []

        if record.get("blocked_by_policy"):
            reasons.append("blocked by command policy")

        if record.get("timed_out"):
            reasons.append("process exceeded timeout")

        if record.get("accessed_sensitive_paths"):
            reasons.append("sensitive filesystem path access")

        if record.get("has_network_activity"):
            reasons.append("network syscall activity")

        if float(record.get("failed_syscalls_count") or 0.0) >= 50:
            reasons.append("high failed syscall count")

        if not reasons:
            reasons.append("no strong anomalous behavior indicators")

        return f"AI prediction is {prediction} with score {score}. Main factors: {', '.join(reasons)}."

    def bootstrap_training_records(self, existing_records: list[dict]) -> list[dict]:
        records = list(existing_records)

        templates = [
            self.template_record("safe-001", 180, 178, 2, 0, 24, 0, False, False, False, False, 0.02),
            self.template_record("safe-002", 160, 155, 2, 0, 18, 0, False, False, False, False, 0.05),
            self.template_record("safe-003", 220, 215, 2, 0, 30, 0, False, False, False, False, 0.10),
            self.template_record("sensitive-001", 350, 347, 2, 0, 24, 1, False, False, False, True, 0.10),
            self.template_record("network-001", 260, 210, 2, 8, 20, 0, False, False, True, False, 0.12),
            self.template_record("blocked-001", 0, 0, 0, 0, 0, 0, True, False, False, False, 0.0),
            self.template_record("timeout-001", 90, 80, 2, 0, 10, 0, False, True, False, False, 0.10),
            self.template_record("failed-syscalls-001", 400, 360, 2, 0, 80, 0, False, False, False, False, 0.20),
        ]

        records.extend(templates)
        return records

    def template_record(
        self,
        run_id: str,
        total_syscalls: int,
        file_syscalls_count: int,
        process_syscalls_count: int,
        network_syscalls_count: int,
        failed_syscalls_count: int,
        sensitive_paths_count: int,
        blocked_by_policy: bool,
        timed_out: bool,
        has_network_activity: bool,
        accessed_sensitive_paths: bool,
        memory_ratio: float,
    ) -> dict:
        return {
            "run_id": run_id,
            "command_hash": run_id,
            "executable": "python",
            "command_length": 2,
            "status": "blocked" if blocked_by_policy else "timed_out" if timed_out else "completed",
            "exit_code": None if blocked_by_policy else 0,
            "policy_allowed": not blocked_by_policy,
            "blocked_by_policy": blocked_by_policy,
            "timed_out": timed_out,
            "killed_by_timeout": timed_out,
            "duration_seconds": 1.0,
            "samples_count": 5,
            "observed_duration_seconds": 1.0,
            "max_cpu_percent": 5.0,
            "avg_cpu_percent": 2.0,
            "max_memory_rss_mb": memory_ratio * 256.0,
            "avg_memory_rss_mb": memory_ratio * 128.0,
            "max_memory_vms_mb": memory_ratio * 300.0,
            "avg_memory_vms_mb": memory_ratio * 150.0,
            "memory_rss_to_limit_ratio": memory_ratio,
            "memory_vms_to_limit_ratio": memory_ratio,
            "max_threads_count": 1,
            "max_children_count": 0,
            "max_open_files_count": 2,
            "open_files_to_limit_ratio": 0.03,
            "observed_statuses_count": 2,
            "errors_count": 0,
            "had_monitoring_errors": False,
            "last_sample_alive": False,
            "non_zero_exit": False,
            "abnormal_termination": blocked_by_policy or timed_out,
            "total_syscalls": total_syscalls,
            "file_syscalls_count": file_syscalls_count,
            "process_syscalls_count": process_syscalls_count,
            "network_syscalls_count": network_syscalls_count,
            "other_syscalls_count": max(0, total_syscalls - file_syscalls_count - process_syscalls_count - network_syscalls_count),
            "successful_syscalls_count": max(0, total_syscalls - failed_syscalls_count),
            "failed_syscalls_count": failed_syscalls_count,
            "unique_syscalls_count": 8,
            "unique_paths_count": 20,
            "sensitive_paths_count": sensitive_paths_count,
            "execve_count": 1 if total_syscalls else 0,
            "openat_count": min(30, file_syscalls_count),
            "access_count": 5 if file_syscalls_count else 0,
            "connect_count": 1 if has_network_activity else 0,
            "has_network_activity": has_network_activity,
            "accessed_sensitive_paths": accessed_sensitive_paths,
        }

    def store_result(self, result: AIInferenceResult) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
