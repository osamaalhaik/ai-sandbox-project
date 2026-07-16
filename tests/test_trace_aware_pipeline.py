import shutil
import unittest
from pathlib import Path

from app.detection.rules import RuleBasedDetector
from app.features.extractor import BehavioralFeatureExtractor
from app.monitoring.sample_summary import ProcessSampleSummarizer
from app.tracing.syscall_summary import SyscallSummarizer
from scripts.run_trace_aware_pipeline import ROOT_DIR, run_traced_command


DATA_FILES = [
    ROOT_DIR / "data/raw/sandbox_runs.jsonl",
    ROOT_DIR / "data/raw/process_samples.jsonl",
    ROOT_DIR / "data/raw/syscall_events.jsonl",
    ROOT_DIR / "data/raw/trace_aware_runs.jsonl",
    ROOT_DIR / "data/processed/process_sample_summaries.jsonl",
    ROOT_DIR / "data/processed/syscall_summaries.jsonl",
    ROOT_DIR / "data/processed/behavioral_features.jsonl",
    ROOT_DIR / "data/processed/detection_results.jsonl",
]


class TraceAwarePipelineTests(unittest.TestCase):
    def setUp(self):
        self.reset_data_files()

    def tearDown(self):
        self.reset_data_files()

    def reset_data_files(self):
        for path in DATA_FILES:
            if path.exists():
                path.unlink()

        trace_dir = ROOT_DIR / "data/raw/strace"

        if trace_dir.exists():
            shutil.rmtree(trace_dir)

    def run_full_trace_aware_pipeline(self, command, **kwargs):
        run_record, trace_record = run_traced_command(
            command=command,
            timeout_seconds=kwargs.get("timeout_seconds", 10),
            max_cpu_seconds=kwargs.get("max_cpu_seconds", 5),
            max_memory_mb=kwargs.get("max_memory_mb", 256),
            max_open_files=kwargs.get("max_open_files", 64),
            working_directory=str(ROOT_DIR),
            monitor_interval_seconds=kwargs.get("monitor_interval_seconds", 0.1),
        )

        process_summary = ProcessSampleSummarizer().summarize(run_record["run_id"])
        syscall_summary = SyscallSummarizer().summarize(run_record["run_id"])
        features = BehavioralFeatureExtractor().extract_by_run_id(run_record["run_id"])
        detection = RuleBasedDetector().detect_by_run_id(run_record["run_id"])

        return run_record, trace_record, process_summary, syscall_summary, features, detection

    def test_safe_trace_aware_pipeline_returns_low_risk(self):
        run_record, trace_record, process_summary, syscall_summary, features, detection = self.run_full_trace_aware_pipeline(
            ["python", "scripts/demo_safe_process.py"]
        )

        self.assertEqual(run_record["status"], "completed")
        self.assertEqual(run_record["policy_allowed"], True)
        self.assertGreater(trace_record["events_count"], 0)
        self.assertGreater(syscall_summary.total_syscalls, 0)
        self.assertGreater(syscall_summary.file_syscalls_count, 0)
        self.assertGreater(syscall_summary.process_syscalls_count, 0)
        self.assertEqual(features.status, "completed")
        self.assertEqual(features.accessed_sensitive_paths, False)
        self.assertEqual(features.has_network_activity, False)
        self.assertEqual(detection.risk_score, 0)
        self.assertEqual(detection.risk_level, "low")
        self.assertEqual(detection.triggered_rules_count, 0)

    def test_traced_execution_excludes_strace_wrapper(self):
        (
            run_record,
            trace_record,
            process_summary,
            syscall_summary,
            features,
            detection,
        ) = self.run_full_trace_aware_pipeline(
            [
                "python",
                "scripts/demo_process_tree.py",
            ],
            monitor_interval_seconds=0.03,
        )

        self.assertEqual(
            run_record["status"],
            "completed",
        )
        self.assertIsNotNone(
            run_record["pid"],
        )
        self.assertEqual(
            run_record["wrapper_pid"],
            run_record["pid"],
        )
        self.assertEqual(
            trace_record["wrapper_pid"],
            run_record["pid"],
        )
        self.assertIsNotNone(
            run_record["target_pid"],
        )
        self.assertNotEqual(
            run_record["target_pid"],
            run_record["wrapper_pid"],
        )
        self.assertIn(
            run_record["target_pid"],
            run_record["monitored_pids"],
        )
        self.assertNotIn(
            run_record["wrapper_pid"],
            run_record["monitored_pids"],
        )
        self.assertGreaterEqual(
            run_record["max_processes_observed"],
            3,
        )
        self.assertEqual(
            trace_record["target_pid"],
            run_record["target_pid"],
        )
        self.assertEqual(
            trace_record["monitored_pids"],
            run_record["monitored_pids"],
        )
        self.assertGreater(
            trace_record["events_count"],
            0,
        )

    def test_blocked_trace_aware_pipeline_returns_high_risk(self):
        run_record, trace_record, process_summary, syscall_summary, features, detection = self.run_full_trace_aware_pipeline(
            ["rm", "-rf", "/tmp/trace-aware-test-blocked"]
        )

        self.assertEqual(run_record["status"], "blocked")
        self.assertEqual(run_record["policy_allowed"], False)
        self.assertEqual(trace_record["events_count"], 0)
        self.assertEqual(process_summary.samples_count, 0)
        self.assertEqual(syscall_summary.total_syscalls, 0)
        self.assertEqual(features.status, "blocked")
        self.assertEqual(features.blocked_by_policy, True)
        self.assertEqual(detection.risk_score, 70)
        self.assertEqual(detection.risk_level, "high")
        self.assertEqual(detection.triggered_rules_count, 1)
        self.assertEqual(detection.triggered_rules[0].rule_id, "POLICY_CONFIRMATION_REQUIRED")


if __name__ == "__main__":
    unittest.main()
