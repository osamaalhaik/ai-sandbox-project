import json
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.web_platform.database import Base
from app.web_platform.models import (
    SecureExecutionRecord,
)
from app.web_platform.secure_execution_store import (
    secure_execution_summary,
    serialize_secure_execution,
    sync_secure_execution_results,
)


class SecureExecutionPersistenceTests(
    unittest.TestCase
):
    def setUp(self):
        self.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        self.path = (
            Path(
                self.temporary_directory.name
            )
            / "secure-executions.jsonl"
        )

        self.engine = create_engine(
            "sqlite://",
            connect_args={
                "check_same_thread": False,
            },
            poolclass=StaticPool,
        )

        Base.metadata.create_all(
            bind=self.engine
        )

        self.Session = sessionmaker(
            bind=self.engine
        )

    def tearDown(self):
        self.engine.dispose()
        self.temporary_directory.cleanup()

    def sample_record(
        self,
        secure_execution_id="secure-1",
    ):
        return {
            "secure_execution_id": (
                secure_execution_id
            ),
            "gateway_decision_id": (
                "gateway-1"
            ),
            "run_id": "run-1",
            "command_text": (
                "python test.py"
            ),
            "working_directory": (
                "/workspace"
            ),
            "execution_strategy": (
                "restricted_sandbox"
            ),
            "execution_profile": (
                "standard"
            ),
            "approval_verified": False,
            "monitoring_enabled": True,
            "status": "completed",
            "failure_reason": None,
            "resource_controls_enabled": True,
            "private_root_enabled": True,
            "private_root_cleaned": True,
            "cgroup_attached": True,
            "cgroup_cleaned": True,
            "cpu_throttled": True,
            "oom_killed": False,
            "pids_limit_hit": False,
            "samples_count": 7,
            "max_processes_observed": 3,
            "profile": {
                "name": "standard",
            },
            "created_at": (
                "2026-07-16T21:00:00+00:00"
            ),
            "finished_at": (
                "2026-07-16T21:00:03+00:00"
            ),
            "run_result": {
                "target_pid": 123,
                "namespace_target_pid": 1,
            },
        }

    def write_records(
        self,
        records,
    ):
        self.path.write_text(
            "".join(
                json.dumps(
                    record,
                    sort_keys=True,
                )
                + "\n"
                for record in records
            ),
            encoding="utf-8",
        )

    def test_import_creates_database_record(self):
        self.write_records(
            [
                self.sample_record(),
            ]
        )

        with self.Session() as session:
            result = (
                sync_secure_execution_results(
                    session,
                    self.path,
                )
            )

            record = session.get(
                SecureExecutionRecord,
                "secure-1",
            )

            self.assertEqual(
                result["imported"],
                1,
            )

            self.assertIsNotNone(
                record
            )

            self.assertEqual(
                record.execution_profile,
                "standard",
            )

            self.assertTrue(
                record.cgroup_attached
            )

    def test_import_is_idempotent_and_updates(self):
        first = self.sample_record()
        self.write_records(
            [
                first,
            ]
        )

        with self.Session() as session:
            sync_secure_execution_results(
                session,
                self.path,
            )

        updated = self.sample_record()
        updated["status"] = "failed"
        updated["oom_killed"] = True

        self.write_records(
            [
                updated,
            ]
        )

        with self.Session() as session:
            result = (
                sync_secure_execution_results(
                    session,
                    self.path,
                )
            )

            record = session.get(
                SecureExecutionRecord,
                "secure-1",
            )

            self.assertEqual(
                result["updated"],
                1,
            )

            self.assertEqual(
                record.status,
                "failed",
            )

            self.assertTrue(
                record.oom_killed
            )

            count = session.query(
                SecureExecutionRecord
            ).count()

            self.assertEqual(
                count,
                1,
            )

    def test_malformed_and_missing_id_are_skipped(self):
        self.path.write_text(
            (
                "{invalid-json}\n"
                + json.dumps(
                    {
                        "status": (
                            "completed"
                        ),
                    }
                )
                + "\n"
            ),
            encoding="utf-8",
        )

        with self.Session() as session:
            result = (
                sync_secure_execution_results(
                    session,
                    self.path,
                )
            )

            self.assertEqual(
                result["malformed"],
                1,
            )

            self.assertEqual(
                result["skipped"],
                1,
            )

            self.assertEqual(
                session.query(
                    SecureExecutionRecord
                ).count(),
                0,
            )

    def test_serializer_decodes_evidence(self):
        self.write_records(
            [
                self.sample_record(),
            ]
        )

        with self.Session() as session:
            sync_secure_execution_results(
                session,
                self.path,
            )

            record = session.get(
                SecureExecutionRecord,
                "secure-1",
            )

            serialized = (
                serialize_secure_execution(
                    record,
                    include_run_result=True,
                )
            )

            self.assertEqual(
                serialized["profile"][
                    "name"
                ],
                "standard",
            )

            self.assertEqual(
                serialized["run_result"][
                    "namespace_target_pid"
                ],
                1,
            )

            self.assertEqual(
                serialized[
                    "samples_count"
                ],
                7,
            )

    def test_summary_counts_security_events(self):
        completed = self.sample_record(
            "secure-completed"
        )

        failed = self.sample_record(
            "secure-failed"
        )

        failed["status"] = "failed"
        failed["cpu_throttled"] = False
        failed["oom_killed"] = True
        failed["pids_limit_hit"] = True
        failed["cgroup_cleaned"] = False

        self.write_records(
            [
                completed,
                failed,
            ]
        )

        with self.Session() as session:
            sync_secure_execution_results(
                session,
                self.path,
            )

            summary = (
                secure_execution_summary(
                    session
                )
            )

            self.assertEqual(
                summary["total"],
                2,
            )

            self.assertEqual(
                summary["completed"],
                1,
            )

            self.assertEqual(
                summary["failed"],
                1,
            )

            self.assertEqual(
                summary["cpu_throttled"],
                1,
            )

            self.assertEqual(
                summary["oom_killed"],
                1,
            )

            self.assertEqual(
                summary["pids_limit_hit"],
                1,
            )

            self.assertEqual(
                summary["cleanup_failures"],
                1,
            )


if __name__ == "__main__":
    unittest.main()
