from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


NAMESPACE_NAMES = (
    "user",
    "mnt",
    "pid",
    "uts",
    "ipc",
    "net",
)


@dataclass(frozen=True)
class PrivateRootProfile:
    network_isolation: bool = True
    hostname_prefix: str = "procsentinel"
    root_size_mb: int = 256
    workspace_size_mb: int = 32
    project_read_only: bool = True


@dataclass
class PrivateRootRunResult:
    run_id: str
    command: list[str]
    launcher_command: list[str]
    working_directory: str
    wrapper_pid: int | None
    status: str
    failure_reason: str | None
    exit_code: int | None
    timed_out: bool
    started_at: str
    finished_at: str
    duration_seconds: float
    stdout: str
    stderr: str
    namespace_enabled: bool
    network_isolated: bool
    private_root_enabled: bool
    root_tmpfs: bool
    project_read_only: bool
    workspace_tmpfs: bool
    workspace_restricted: bool
    proc_mounted: bool
    minimal_etc: bool
    host_root_hidden: bool
    proc_root_private: bool
    capabilities_dropped: bool
    no_new_privileges_enabled: bool
    private_root_dir: str
    private_root_cleaned: bool
    namespace_checks: dict[str, bool]
    host_namespaces: dict[str, str | None]
    child_evidence: dict
    profile: dict


class PrivateRootRunner:
    def __init__(
        self,
        output_path: str = (
            "data/raw/private_root_runs.jsonl"
        ),
        unshare_path: str | None = None,
    ):
        resolved = (
            unshare_path
            or shutil.which(
                "unshare"
            )
        )

        if not resolved:
            raise RuntimeError(
                "unshare executable was not found"
            )

        self.unshare_path = resolved

        self.output_path = Path(
            output_path
        )

        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def preflight(self) -> dict:
        userns_enabled = self._read_integer(
            Path(
                "/proc/sys/kernel/"
                "unprivileged_userns_clone"
            ),
            default=1,
        )

        maximum_user_namespaces = (
            self._read_integer(
                Path(
                    "/proc/sys/user/"
                    "max_user_namespaces"
                ),
                default=0,
            )
        )

        required_commands = {
            name: shutil.which(name)
            for name in (
                "unshare",
                "mount",
            )
        }

        commands_available = all(
            required_commands.values()
        )

        return {
            "linux": (
                sys.platform.startswith(
                    "linux"
                )
            ),
            "unprivileged_userns_clone": (
                userns_enabled
            ),
            "max_user_namespaces": (
                maximum_user_namespaces
            ),
            "commands": required_commands,
            "available": (
                sys.platform.startswith(
                    "linux"
                )
                and userns_enabled == 1
                and maximum_user_namespaces
                > 0
                and commands_available
            ),
        }

    def run(
        self,
        command: list[str],
        working_directory: str | None = None,
        timeout_seconds: float = 10,
        profile: PrivateRootProfile | None = None,
    ) -> PrivateRootRunResult:
        selected_profile = (
            profile
            or PrivateRootProfile()
        )

        if not command:
            raise ValueError(
                "command must not be empty"
            )

        preflight = self.preflight()

        if not preflight[
            "available"
        ]:
            raise RuntimeError(
                "Private-root execution is unavailable"
            )

        run_id = str(
            uuid.uuid4()
        )

        evidence_token = (
            secrets.token_urlsafe(
                18
            )
        )

        hostname = (
            f"{selected_profile.hostname_prefix}-"
            f"{run_id[:8]}"
        )[:63]

        resolved_working_directory = str(
            Path(
                working_directory
                or os.getcwd()
            ).resolve()
        )

        root_parent = (
            Path(
                tempfile.gettempdir()
            )
            / "procsentinel-private-roots"
        )

        root_parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        private_root_dir = (
            root_parent
            / run_id
        )

        private_root_dir.mkdir(
            parents=False,
            exist_ok=False,
            mode=0o700,
        )

        host_namespaces = (
            self._namespace_links(
                "self"
            )
        )

        launcher_command = (
            self._build_command(
                command=command,
                evidence_token=(
                    evidence_token
                ),
                hostname=hostname,
                project_dir=(
                    resolved_working_directory
                ),
                private_root_dir=str(
                    private_root_dir
                ),
                profile=(
                    selected_profile
                ),
            )
        )

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        started_monotonic = (
            time.monotonic()
        )

        process = None
        stdout = ""
        stderr = ""
        exit_code = None
        timed_out = False
        failure_reason = None

        try:
            process = subprocess.Popen(
                launcher_command,
                cwd=(
                    resolved_working_directory
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

            try:
                stdout, stderr = (
                    process.communicate(
                        timeout=(
                            timeout_seconds
                        )
                    )
                )

                exit_code = (
                    process.returncode
                )

            except subprocess.TimeoutExpired:
                timed_out = True

                failure_reason = (
                    "private_root_timeout_exceeded"
                )

                os.killpg(
                    process.pid,
                    signal.SIGKILL,
                )

                stdout, stderr = (
                    process.communicate()
                )

                exit_code = (
                    process.returncode
                )

        except FileNotFoundError as exc:
            stderr = str(exc)

            failure_reason = (
                "private_root_launcher_not_found"
            )

        except PermissionError as exc:
            stderr = str(exc)

            failure_reason = (
                "private_root_permission_denied"
            )

        except Exception as exc:
            stderr = str(exc)

            failure_reason = (
                "private_root_launcher_error"
            )

        evidence, cleaned_stderr = (
            self._extract_evidence(
                stderr=stderr,
                token=evidence_token,
            )
        )

        private_root = evidence.get(
            "private_root",
            {},
        )

        namespace_checks = (
            self._namespace_checks(
                host_namespaces=(
                    host_namespaces
                ),
                child_evidence=(
                    evidence
                ),
                profile=(
                    selected_profile
                ),
            )
        )

        namespace_enabled = (
            bool(evidence)
            and evidence.get("pid") == 1
            and all(
                namespace_checks.values()
            )
        )

        network_isolated = bool(
            namespace_checks.get(
                "net",
                False,
            )
        )

        private_root_enabled = bool(
            private_root.get(
                "enabled"
            )
        )

        root_tmpfs = bool(
            private_root.get(
                "root_tmpfs"
            )
        )

        project_read_only = bool(
            private_root.get(
                "project_read_only"
            )
        )

        workspace_tmpfs = bool(
            private_root.get(
                "workspace_tmpfs"
            )
        )

        workspace_restricted = bool(
            private_root.get(
                "workspace_restricted"
            )
        )

        proc_mounted = bool(
            private_root.get(
                "proc_mounted"
            )
        )

        minimal_etc = bool(
            private_root.get(
                "minimal_etc"
            )
        )

        host_root_hidden = bool(
            private_root.get(
                "host_root_hidden"
            )
        )

        proc_root_private = bool(
            evidence.get(
                "proc_root_private"
            )
        )

        capabilities_dropped = bool(
            evidence.get(
                "capabilities_dropped"
            )
        )

        no_new_privileges_enabled = bool(
            evidence.get(
                "no_new_privileges"
            )
        )

        validation_passed = all(
            (
                namespace_enabled,
                private_root_enabled,
                root_tmpfs,
                workspace_tmpfs,
                workspace_restricted,
                proc_mounted,
                minimal_etc,
                host_root_hidden,
                proc_root_private,
                capabilities_dropped,
                no_new_privileges_enabled,
                (
                    not selected_profile
                    .project_read_only
                    or project_read_only
                ),
                (
                    not selected_profile
                    .network_isolation
                    or network_isolated
                ),
            )
        )

        if timed_out:
            status = "timed_out"

        elif (
            exit_code == 0
            and validation_passed
        ):
            status = "completed"

        elif (
            exit_code == 0
            and not evidence
        ):
            status = "failed"

            failure_reason = (
                "private_root_evidence_missing"
            )

        elif (
            exit_code == 0
            and not validation_passed
        ):
            status = "failed"

            failure_reason = (
                "private_root_validation_failed"
            )

        else:
            status = "failed"

            if failure_reason is None:
                failure_reason = (
                    "private_root_target_failed"
                )

        shutil.rmtree(
            private_root_dir,
            ignore_errors=True,
        )

        private_root_cleaned = (
            not private_root_dir.exists()
        )

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        result = PrivateRootRunResult(
            run_id=run_id,
            command=command,
            launcher_command=(
                launcher_command
            ),
            working_directory=(
                resolved_working_directory
            ),
            wrapper_pid=(
                process.pid
                if process is not None
                else None
            ),
            status=status,
            failure_reason=(
                failure_reason
            ),
            exit_code=exit_code,
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(
                time.monotonic()
                - started_monotonic,
                4,
            ),
            stdout=stdout,
            stderr=cleaned_stderr,
            namespace_enabled=(
                namespace_enabled
            ),
            network_isolated=(
                network_isolated
            ),
            private_root_enabled=(
                private_root_enabled
            ),
            root_tmpfs=root_tmpfs,
            project_read_only=(
                project_read_only
            ),
            workspace_tmpfs=(
                workspace_tmpfs
            ),
            workspace_restricted=(
                workspace_restricted
            ),
            proc_mounted=(
                proc_mounted
            ),
            minimal_etc=(
                minimal_etc
            ),
            host_root_hidden=(
                host_root_hidden
            ),
            proc_root_private=(
                proc_root_private
            ),
            capabilities_dropped=(
                capabilities_dropped
            ),
            no_new_privileges_enabled=(
                no_new_privileges_enabled
            ),
            private_root_dir=str(
                private_root_dir
            ),
            private_root_cleaned=(
                private_root_cleaned
            ),
            namespace_checks=(
                namespace_checks
            ),
            host_namespaces=(
                host_namespaces
            ),
            child_evidence=(
                evidence
            ),
            profile=asdict(
                selected_profile
            ),
        )

        self._store_result(
            result
        )

        return result

    def _build_command(
        self,
        command: list[str],
        evidence_token: str,
        hostname: str,
        project_dir: str,
        private_root_dir: str,
        profile: PrivateRootProfile,
    ) -> list[str]:
        result = [
            self.unshare_path,
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child=KILL",
            "--uts",
            "--ipc",
        ]

        if profile.network_isolation:
            result.append(
                "--net"
            )

        result.extend(
            [
                sys.executable,
                "-m",
                (
                    "app.sandbox."
                    "private_root_entrypoint"
                ),
                (
                    "--evidence-token="
                    f"{evidence_token}"
                ),
                (
                    "--hostname="
                    f"{hostname}"
                ),
                (
                    "--project-dir="
                    f"{project_dir}"
                ),
                (
                    "--private-root-dir="
                    f"{private_root_dir}"
                ),
                (
                    "--root-size-mb="
                    f"{profile.root_size_mb}"
                ),
                (
                    "--workspace-size-mb="
                    f"{profile.workspace_size_mb}"
                ),
                (
                    "--project-read-only="
                    + (
                        "true"
                        if profile.project_read_only
                        else "false"
                    )
                ),
                "--",
                *command,
            ]
        )

        return result

    def _namespace_checks(
        self,
        host_namespaces: dict[
            str,
            str | None,
        ],
        child_evidence: dict,
        profile: PrivateRootProfile,
    ) -> dict[str, bool]:
        child_namespaces = (
            child_evidence.get(
                "namespaces",
                {},
            )
        )

        required = [
            "user",
            "mnt",
            "pid",
            "uts",
            "ipc",
        ]

        if profile.network_isolation:
            required.append(
                "net"
            )

        return {
            name: bool(
                child_namespaces.get(
                    name
                )
                and host_namespaces.get(
                    name
                )
                and child_namespaces.get(
                    name
                )
                != host_namespaces.get(
                    name
                )
            )
            for name in required
        }

    def _extract_evidence(
        self,
        stderr: str,
        token: str,
    ) -> tuple[dict, str]:
        prefix = (
            "PROCSENTINEL_PRIVATE_ROOT_EVIDENCE"
            f"::{token}::"
        )

        evidence = {}
        retained_lines = []

        for line in stderr.splitlines():
            if line.startswith(prefix):
                encoded = line[
                    len(prefix):
                ]

                try:
                    payload = (
                        base64.urlsafe_b64decode(
                            encoded.encode(
                                "ascii"
                            )
                        )
                    )

                    evidence = json.loads(
                        payload.decode(
                            "utf-8"
                        )
                    )

                except Exception:
                    retained_lines.append(
                        "private_root_evidence_decode_failed"
                    )

                continue

            retained_lines.append(line)

        cleaned = "\n".join(
            retained_lines
        )

        if (
            stderr.endswith("\n")
            and cleaned
        ):
            cleaned += "\n"

        return evidence, cleaned

    def _namespace_links(
        self,
        process_id: str | int,
    ) -> dict[str, str | None]:
        values = {}

        for name in NAMESPACE_NAMES:
            path = Path(
                f"/proc/{process_id}/ns/{name}"
            )

            try:
                values[name] = os.readlink(
                    path
                )
            except OSError:
                values[name] = None

        return values

    def _read_integer(
        self,
        path: Path,
        default: int,
    ) -> int:
        try:
            return int(
                path.read_text(
                    encoding="utf-8"
                ).strip()
            )

        except (
            OSError,
            ValueError,
        ):
            return default

    def _store_result(
        self,
        result: PrivateRootRunResult,
    ) -> None:
        with self.output_path.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(
                json.dumps(
                    asdict(result),
                    ensure_ascii=False,
                )
                + "\n"
            )
