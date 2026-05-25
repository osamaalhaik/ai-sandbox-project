import json
import tempfile
import unittest
from pathlib import Path

from app.monitoring.sample_summary import ProcessSampleSummarizer


class ProcessSampleSummaryTests(unittest.TestCase):
    def create_paths(self):
        temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(temp_dir.name)
        samples_path = base_path / "process_samples.jsonl"
        summaries_path = base_path / "process_sample_summaries.jsonl"
        return temp_dir, samples_path, summaries_path

    def write_samples(self, samples_path, records):
        with samples_path.open("w", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record) + "\n")

    def read_jsonl(self, path):
        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_missing_run_id_returns_empty_summary(self):
        temp_dir, samples_path, summaries_path = self.create_paths()

        try:
            summarizer = ProcessSampleSummarizer(
                samples_path=str(samples_path),
                output_path=str(summaries_path),
            )

            summary = summarizer.summarize("missing-run", persist=False)

            self.assertEqual(summary.run_id, "missing-run")
            self.assertEqual(summary.samples_count, 0)
            self.assertEqual(summary.observed_duration_seconds, 0.0)
            self.assertEqual(summary.max_cpu_percent, 0.0)
            self.assertEqual(summary.avg_cpu_percent, 0.0)
            self.assertEqual(summary.max_memory_rss_mb, 0.0)
            self.assertEqual(summary.avg_memory_rss_mb, 0.0)
            self.assertEqual(summary.observed_statuses, [])
            self.assertEqual(summary.errors_count, 0)
            self.assertFalse(summary.had_errors)
            self.assertFalse(summary.last_sample_alive)
        finally:
            temp_dir.cleanup()

    def test_summary_metrics_are_calculated_from_samples(self):
        temp_dir, samples_path, summaries_path = self.create_paths()

        try:
            run_id = "run-123"

            records = [
                {
                    "run_id": run_id,
                    "pid": 100,
                    "timestamp": "2026-05-25T00:00:00+00:00",
                    "status": "running",
                    "cpu_percent": 10.0,
                    "memory_rss_mb": 5.0,
                    "memory_vms_mb": 50.0,
                    "threads_count": 1,
                    "children_count": 0,
                    "open_files_count": 0,
                    "alive": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "pid": 100,
                    "timestamp": "2026-05-25T00:00:01+00:00",
                    "status": "sleeping",
                    "cpu_percent": 20.0,
                    "memory_rss_mb": 15.0,
                    "memory_vms_mb": 80.0,
                    "threads_count": 2,
                    "children_count": 1,
                    "open_files_count": 3,
                    "alive": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "pid": 100,
                    "timestamp": "2026-05-25T00:00:02.500000+00:00",
                    "status": None,
                    "cpu_percent": 0.0,
                    "memory_rss_mb": 10.0,
                    "memory_vms_mb": 70.0,
                    "threads_count": 1,
                    "children_count": 0,
                    "open_files_count": 1,
                    "alive": False,
                    "error": "no_such_process",
                },
            ]

            self.write_samples(samples_path, records)

            summarizer = ProcessSampleSummarizer(
                samples_path=str(samples_path),
                output_path=str(summaries_path),
            )

            summary = summarizer.summarize(run_id, persist=False)

            self.assertEqual(summary.samples_count, 3)
            self.assertEqual(summary.observed_duration_seconds, 2.5)
            self.assertEqual(summary.max_cpu_percent, 20.0)
            self.assertEqual(summary.avg_cpu_percent, 10.0)
            self.assertEqual(summary.max_memory_rss_mb, 15.0)
            self.assertEqual(summary.avg_memory_rss_mb, 10.0)
            self.assertEqual(summary.max_memory_vms_mb, 80.0)
            self.assertEqual(summary.avg_memory_vms_mb, 66.6667)
            self.assertEqual(summary.max_threads_count, 2)
            self.assertEqual(summary.max_children_count, 1)
            self.assertEqual(summary.max_open_files_count, 3)
            self.assertEqual(summary.observed_statuses, ["running", "sleeping"])
            self.assertEqual(summary.errors_count, 1)
            self.assertTrue(summary.had_errors)
            self.assertFalse(summary.last_sample_alive)
        finally:
            temp_dir.cleanup()

    def test_summary_is_persisted_to_output_jsonl(self):
        temp_dir, samples_path, summaries_path = self.create_paths()

        try:
            run_id = "run-456"

            records = [
                {
                    "run_id": run_id,
                    "pid": 200,
                    "timestamp": "2026-05-25T00:00:00+00:00",
                    "status": "running",
                    "cpu_percent": 5.0,
                    "memory_rss_mb": 8.0,
                    "memory_vms_mb": 40.0,
                    "threads_count": 1,
                    "children_count": 0,
                    "open_files_count": 2,
                    "alive": True,
                    "error": None,
                }
            ]

            self.write_samples(samples_path, records)

            summarizer = ProcessSampleSummarizer(
                samples_path=str(samples_path),
                output_path=str(summaries_path),
            )

            summary = summarizer.summarize(run_id, persist=True)
            persisted_records = self.read_jsonl(summaries_path)

            self.assertEqual(len(persisted_records), 1)
            self.assertEqual(persisted_records[0]["run_id"], summary.run_id)
            self.assertEqual(persisted_records[0]["samples_count"], 1)
            self.assertEqual(persisted_records[0]["max_open_files_count"], 2)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
