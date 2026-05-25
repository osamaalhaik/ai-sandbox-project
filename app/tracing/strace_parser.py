import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class SyscallEvent:
    run_id: str
    line_number: int
    raw_line: str
    pid: int | None
    timestamp: str | None
    syscall: str
    category: str
    path: str | None
    result: str | None
    success: bool | None
    error: str | None


class StraceParser:
    def __init__(self, output_path: str = "data/raw/syscall_events.jsonl"):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.line_pattern = re.compile(
            r'^\s*(?:\[pid\s+(?P<pid_bracket>\d+)\]\s+|(?P<pid_plain>\d+)\s+)?(?P<timestamp>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$'
        )
        self.path_pattern = re.compile(r'"([^"]+)"')

    def parse_file(self, run_id: str, log_path: str, persist: bool = True) -> list[SyscallEvent]:
        path = Path(log_path)

        if not path.exists():
            return []

        events = []

        for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            event = self.parse_line(run_id, index, line)

            if event is not None:
                events.append(event)

        if persist:
            self.store_events(events)

        return events

    def parse_line(self, run_id: str, line_number: int, raw_line: str) -> SyscallEvent | None:
        match = self.line_pattern.match(raw_line)

        if match is None:
            return None

        pid_value = match.group("pid_bracket") or match.group("pid_plain")
        syscall = match.group("syscall")
        args = match.group("args")
        result = match.group("result").strip()

        return SyscallEvent(
            run_id=run_id,
            line_number=line_number,
            raw_line=raw_line,
            pid=int(pid_value) if pid_value else None,
            timestamp=match.group("timestamp"),
            syscall=syscall,
            category=self.category(syscall),
            path=self.extract_path(args),
            result=result,
            success=self.success(result),
            error=self.extract_error(result),
        )

    def category(self, syscall: str) -> str:
        file_syscalls = {
            "open",
            "openat",
            "creat",
            "readlink",
            "stat",
            "lstat",
            "fstat",
            "newfstatat",
            "access",
            "faccessat",
            "unlink",
            "unlinkat",
            "rename",
            "renameat",
            "mkdir",
            "mkdirat",
            "rmdir",
            "chmod",
            "fchmod",
            "chown",
            "fchown",
            "getcwd",
        }

        process_syscalls = {
            "execve",
            "clone",
            "clone3",
            "fork",
            "vfork",
            "wait4",
            "waitpid",
            "exit",
            "exit_group",
            "kill",
            "tgkill",
        }

        network_syscalls = {
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "getsockname",
            "getpeername",
        }

        if syscall in file_syscalls:
            return "file"

        if syscall in process_syscalls:
            return "process"

        if syscall in network_syscalls:
            return "network"

        return "other"

    def extract_path(self, args: str) -> str | None:
        match = self.path_pattern.search(args)

        if match is None:
            return None

        return match.group(1)

    def success(self, result: str) -> bool | None:
        if not result:
            return None

        if result.startswith("-1"):
            return False

        if result.startswith("?"):
            return None

        return True

    def extract_error(self, result: str) -> str | None:
        if not result.startswith("-1"):
            return None

        parts = result.split()

        if len(parts) >= 2:
            return parts[1]

        return "UNKNOWN"

    def store_events(self, events: list[SyscallEvent]) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            for event in events:
                file.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
