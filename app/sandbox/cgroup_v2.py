from __future__ import annotations

import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


REQUIRED_CONTROLLERS = (
    "cpu",
    "memory",
    "pids",
)


@dataclass(frozen=True)
class CgroupV2Limits:
    cpu_quota_us: int = 50000
    cpu_period_us: int = 100000
    memory_max_bytes: int = 134217728
    memory_high_bytes: int | None = None
    memory_swap_max_bytes: int = 0
    pids_max: int = 64

    def validate(self) -> None:
        if self.cpu_period_us < 1000:
            raise ValueError(
                "cpu_period_us must be at least 1000"
            )

        if self.cpu_quota_us < 1000:
            raise ValueError(
                "cpu_quota_us must be at least 1000"
            )

        if self.cpu_quota_us > self.cpu_period_us * 64:
            raise ValueError(
                "cpu_quota_us is unreasonably large"
            )

        if self.memory_max_bytes < 16777216:
            raise ValueError(
                "memory_max_bytes must be at least 16 MiB"
            )

        if (
            self.memory_high_bytes is not None
            and self.memory_high_bytes
            > self.memory_max_bytes
        ):
            raise ValueError(
                "memory_high_bytes exceeds memory_max_bytes"
            )

        if self.memory_swap_max_bytes < 0:
            raise ValueError(
                "memory_swap_max_bytes must not be negative"
            )

        if self.pids_max < 4:
            raise ValueError(
                "pids_max must be at least 4"
            )


@dataclass
class CgroupV2Handle:
    run_id: str
    path: str
    limits: dict
    created_at: str


class CgroupV2Manager:
    def __init__(
        self,
        cgroup_mount: str = "/sys/fs/cgroup",
        delegated_root: str | None = None,
        manager_name: str = "manager",
    ):
        self.cgroup_mount = Path(
            cgroup_mount
        ).resolve()

        self.manager_name = self._safe_name(
            manager_name
        )

        if delegated_root is None:
            current_path = (
                self.cgroup_mount
                / self.current_relative_path().lstrip(
                    "/"
                )
            )

            if (
                current_path.name
                == self.manager_name
            ):
                current_path = (
                    current_path.parent
                )

            self.delegated_root = (
                current_path
            )
        else:
            self.delegated_root = Path(
                delegated_root
            ).resolve()

        self.manager_path = (
            self.delegated_root
            / self.manager_name
        )

        self._prepared = False

    @staticmethod
    def current_relative_path(
        proc_cgroup_path: str = "/proc/self/cgroup",
    ) -> str:
        for line in Path(
            proc_cgroup_path
        ).read_text(
            encoding="utf-8"
        ).splitlines():
            parts = line.split(
                ":",
                2,
            )

            if (
                len(parts) == 3
                and parts[0] == "0"
            ):
                return parts[2]

        raise RuntimeError(
            "unified cgroup path was not found"
        )

    def preflight(self) -> dict:
        controllers = self._read_tokens(
            self.delegated_root
            / "cgroup.controllers"
        )

        missing = sorted(
            set(REQUIRED_CONTROLLERS)
            - controllers
        )

        return {
            "cgroup_mount": str(
                self.cgroup_mount
            ),
            "delegated_root": str(
                self.delegated_root
            ),
            "controllers": sorted(
                controllers
            ),
            "missing_controllers": (
                missing
            ),
            "cgroup_procs_writable": (
                os.access(
                    self.delegated_root
                    / "cgroup.procs",
                    os.W_OK,
                )
            ),
            "subtree_control_writable": (
                os.access(
                    self.delegated_root
                    / "cgroup.subtree_control",
                    os.W_OK,
                )
            ),
            "available": (
                not missing
                and os.access(
                    self.delegated_root
                    / "cgroup.procs",
                    os.W_OK,
                )
                and os.access(
                    self.delegated_root
                    / "cgroup.subtree_control",
                    os.W_OK,
                )
            ),
        }

    def prepare(self) -> dict:
        preflight = self.preflight()

        if not preflight["available"]:
            raise RuntimeError(
                "cgroup_v2_delegation_unavailable:"
                + ",".join(
                    preflight[
                        "missing_controllers"
                    ]
                )
            )

        self.manager_path.mkdir(
            exist_ok=True
        )

        root_processes = self._read_pids(
            self.delegated_root
            / "cgroup.procs"
        )

        for process_id in root_processes:
            self._write_value(
                self.manager_path
                / "cgroup.procs",
                str(process_id),
            )

        enabled = self._read_tokens(
            self.delegated_root
            / "cgroup.subtree_control"
        )

        missing = [
            controller
            for controller
            in REQUIRED_CONTROLLERS
            if controller not in enabled
        ]

        if missing:
            self._write_value(
                self.delegated_root
                / "cgroup.subtree_control",
                " ".join(
                    f"+{controller}"
                    for controller in missing
                ),
            )

        enabled_after = self._read_tokens(
            self.delegated_root
            / "cgroup.subtree_control"
        )

        enabled_after = {
            value.lstrip(
                "+-"
            )
            for value in enabled_after
        }

        unresolved = sorted(
            set(REQUIRED_CONTROLLERS)
            - enabled_after
        )

        if unresolved:
            raise RuntimeError(
                "cgroup_controllers_not_enabled:"
                + ",".join(
                    unresolved
                )
            )

        self._prepared = True

        return {
            **preflight,
            "manager_path": str(
                self.manager_path
            ),
            "moved_processes": (
                root_processes
            ),
            "subtree_control": sorted(
                enabled_after
            ),
            "prepared": True,
        }

    def create_run(
        self,
        run_id: str,
        limits: CgroupV2Limits,
    ) -> CgroupV2Handle:
        limits.validate()

        if not self._prepared:
            self.prepare()

        safe_run_id = self._safe_name(
            run_id
        )

        path = (
            self.delegated_root
            / f"run-{safe_run_id}"
        )

        path.mkdir(
            exist_ok=False
        )

        self._write_value(
            path / "cpu.max",
            (
                f"{limits.cpu_quota_us} "
                f"{limits.cpu_period_us}"
            ),
        )

        self._write_value(
            path / "memory.max",
            str(
                limits.memory_max_bytes
            ),
        )

        self._write_value(
            path / "memory.high",
            (
                str(
                    limits.memory_high_bytes
                )
                if limits.memory_high_bytes
                is not None
                else "max"
            ),
        )

        self._write_value(
            path / "memory.swap.max",
            str(
                limits.memory_swap_max_bytes
            ),
        )

        self._write_value(
            path / "pids.max",
            str(
                limits.pids_max
            ),
        )

        return CgroupV2Handle(
            run_id=run_id,
            path=str(path),
            limits=asdict(
                limits
            ),
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )

    def attach_pid(
        self,
        handle: CgroupV2Handle,
        process_id: int,
    ) -> None:
        if process_id <= 0:
            raise ValueError(
                "process_id must be positive"
            )

        self._write_value(
            Path(handle.path)
            / "cgroup.procs",
            str(process_id),
        )

    def snapshot(
        self,
        handle: CgroupV2Handle,
    ) -> dict:
        path = Path(
            handle.path
        )

        cpu_stat = self._read_key_values(
            path / "cpu.stat"
        )

        memory_events = self._read_key_values(
            path / "memory.events"
        )

        memory_events_local = (
            self._read_key_values(
                path
                / "memory.events.local"
            )
        )

        pids_events = self._read_key_values(
            path / "pids.events"
        )

        cgroup_events = self._read_key_values(
            path / "cgroup.events"
        )

        return {
            "run_id": handle.run_id,
            "path": handle.path,
            "limits": handle.limits,
            "cpu_max": self._read_value(
                path / "cpu.max"
            ),
            "cpu_stat": cpu_stat,
            "memory_current": (
                self._read_integer_value(
                    path
                    / "memory.current"
                )
            ),
            "memory_peak": (
                self._read_integer_value(
                    path
                    / "memory.peak"
                )
            ),
            "memory_max": self._read_value(
                path / "memory.max"
            ),
            "memory_high": self._read_value(
                path / "memory.high"
            ),
            "memory_swap_max": (
                self._read_value(
                    path
                    / "memory.swap.max"
                )
            ),
            "memory_events": (
                memory_events
            ),
            "memory_events_local": (
                memory_events_local
            ),
            "pids_current": (
                self._read_integer_value(
                    path
                    / "pids.current"
                )
            ),
            "pids_max": self._read_value(
                path / "pids.max"
            ),
            "pids_events": pids_events,
            "cgroup_events": (
                cgroup_events
            ),
            "cpu_throttled": (
                cpu_stat.get(
                    "nr_throttled",
                    0,
                )
                > 0
            ),
            "oom_killed": (
                memory_events.get(
                    "oom_kill",
                    0,
                )
                > 0
            ),
            "pids_limit_hit": (
                pids_events.get(
                    "max",
                    0,
                )
                > 0
            ),
            "captured_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

    def cleanup(
        self,
        handle: CgroupV2Handle,
        kill_remaining: bool = False,
        retries: int = 50,
    ) -> bool:
        path = Path(
            handle.path
        )

        if not path.exists():
            return True

        if (
            kill_remaining
            and (
                path / "cgroup.kill"
            ).exists()
        ):
            try:
                self._write_value(
                    path
                    / "cgroup.kill",
                    "1",
                )
            except OSError:
                pass

        for _ in range(
            max(
                1,
                retries,
            )
        ):
            try:
                path.rmdir()
                return True
            except FileNotFoundError:
                return True
            except OSError:
                time.sleep(
                    0.02
                )

        return False

    def _safe_name(
        self,
        value: str,
    ) -> str:
        result = re.sub(
            r"[^A-Za-z0-9_.-]+",
            "-",
            value.strip(),
        ).strip(
            ".-"
        )

        if not result:
            raise ValueError(
                "invalid cgroup name"
            )

        return result[:96]

    def _write_value(
        self,
        path: Path,
        value: str,
    ) -> None:
        with path.open(
            "w",
            encoding="utf-8",
        ) as file:
            file.write(
                value
            )

    def _read_value(
        self,
        path: Path,
    ) -> str | None:
        try:
            return path.read_text(
                encoding="utf-8"
            ).strip()
        except OSError:
            return None

    def _read_integer_value(
        self,
        path: Path,
    ) -> int | None:
        value = self._read_value(
            path
        )

        if value is None:
            return None

        try:
            return int(
                value
            )
        except ValueError:
            return None

    def _read_tokens(
        self,
        path: Path,
    ) -> set[str]:
        value = self._read_value(
            path
        )

        if not value:
            return set()

        return {
            item.lstrip(
                "+-"
            )
            for item in value.split()
        }

    def _read_pids(
        self,
        path: Path,
    ) -> list[int]:
        value = self._read_value(
            path
        )

        if not value:
            return []

        result = []

        for line in value.splitlines():
            try:
                result.append(
                    int(
                        line.strip()
                    )
                )
            except ValueError:
                continue

        return result

    def _read_key_values(
        self,
        path: Path,
    ) -> dict[str, int]:
        value = self._read_value(
            path
        )

        if not value:
            return {}

        result = {}

        for line in value.splitlines():
            parts = line.split()

            if len(parts) != 2:
                continue

            try:
                result[
                    parts[0]
                ] = int(
                    parts[1]
                )
            except ValueError:
                continue

        return result
