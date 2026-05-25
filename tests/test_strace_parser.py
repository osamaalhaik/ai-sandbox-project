import json
import tempfile
import unittest
from pathlib import Path

from app.tracing.strace_parser import StraceParser


class StraceParserTests(unittest.TestCase):
    def create_parser(self):
        temp_dir = tempfile.TemporaryDirectory()
        output_path = Path(temp_dir.name) / "syscall_events.jsonl"
        parser = StraceParser(output_path=str(output_path))
        return temp_dir, output_path, parser

    def read_jsonl(self, path):
        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_parse_execve_process_syscall(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            line = '22714 01:49:01.042203 execve("/usr/bin/python", ["python", "script.py"], 0x7fff) = 0'
            event = parser.parse_line("run-001", 1, line)

            self.assertIsNotNone(event)
            self.assertEqual(event.run_id, "run-001")
            self.assertEqual(event.pid, 22714)
            self.assertEqual(event.timestamp, "01:49:01.042203")
            self.assertEqual(event.syscall, "execve")
            self.assertEqual(event.category, "process")
            self.assertEqual(event.path, "/usr/bin/python")
            self.assertEqual(event.result, "0")
            self.assertTrue(event.success)
            self.assertIsNone(event.error)
        finally:
            temp_dir.cleanup()

    def test_parse_openat_file_syscall(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            line = '22714 01:49:01.053418 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3'
            event = parser.parse_line("run-002", 2, line)

            self.assertIsNotNone(event)
            self.assertEqual(event.syscall, "openat")
            self.assertEqual(event.category, "file")
            self.assertEqual(event.path, "/etc/ld.so.cache")
            self.assertEqual(event.result, "3")
            self.assertTrue(event.success)
            self.assertIsNone(event.error)
        finally:
            temp_dir.cleanup()

    def test_parse_connect_network_syscall(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            line = '22714 01:49:01.100000 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0'
            event = parser.parse_line("run-003", 3, line)

            self.assertIsNotNone(event)
            self.assertEqual(event.syscall, "connect")
            self.assertEqual(event.category, "network")
            self.assertIsNone(event.path)
            self.assertEqual(event.result, "0")
            self.assertTrue(event.success)
        finally:
            temp_dir.cleanup()

    def test_parse_failed_syscall_error(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            line = '22714 01:49:01.051657 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)'
            event = parser.parse_line("run-004", 4, line)

            self.assertIsNotNone(event)
            self.assertEqual(event.syscall, "access")
            self.assertEqual(event.category, "file")
            self.assertEqual(event.path, "/etc/ld.so.preload")
            self.assertFalse(event.success)
            self.assertEqual(event.error, "ENOENT")
        finally:
            temp_dir.cleanup()

    def test_unknown_syscall_is_other_category(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            line = '22714 01:49:01.200000 uname({sysname="Linux"}) = 0'
            event = parser.parse_line("run-005", 5, line)

            self.assertIsNotNone(event)
            self.assertEqual(event.syscall, "uname")
            self.assertEqual(event.category, "other")
            self.assertTrue(event.success)
        finally:
            temp_dir.cleanup()

    def test_unmatched_line_returns_none(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            line = "this is not a valid strace line"
            event = parser.parse_line("run-006", 6, line)

            self.assertIsNone(event)
        finally:
            temp_dir.cleanup()

    def test_parse_file_persists_events(self):
        temp_dir, output_path, parser = self.create_parser()

        try:
            log_path = Path(temp_dir.name) / "trace.log"
            log_path.write_text(
                "\n".join(
                    [
                        '22714 01:49:01.042203 execve("/usr/bin/python", ["python"], 0x7fff) = 0',
                        '22714 01:49:01.053418 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3',
                        'not a valid line',
                    ]
                ),
                encoding="utf-8",
            )

            events = parser.parse_file("run-007", str(log_path), persist=True)
            records = self.read_jsonl(output_path)

            self.assertEqual(len(events), 2)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["run_id"], "run-007")
            self.assertEqual(records[0]["syscall"], "execve")
            self.assertEqual(records[1]["syscall"], "openat")
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
