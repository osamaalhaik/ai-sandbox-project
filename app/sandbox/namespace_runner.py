from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
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
class NamespaceProfile:
    network_isolation: bool = True
    mount_proc: bool = True
    hostname_prefix: str = "procsentinel"


@dataclass
class NamespaceRunResult:
    run_id: str
    command: list[str]
    namespace_command: list[str]
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
    no_new_privileges_enabled: bool
    capabilities_dropped: bool
    namespace_checks: dict[str, bool]
    host_namespaces: dict[str, str | None]
    child_evidence: dict
    profile: dict


class NamespaceRunner:
    def __init__(
        self,
        output_path: str = (
            "data/raw/namespace_runs.jsonl"
        ),
        unshare_path: str | None = None,
    ):
        resolved = (
            unshare_path
            or shutil.which("unshare")
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

        return {
            "linux": sys.platform.startswith(
                "linux"
            ),
            "unshare_path": (
                self.unshare_path
            ),
            "unprivileged_userns_clone": (
                userns_enabled
            ),
            "max_user_namespaces": (
                maximum_user_namespaces
            ),
            "available": (
                sys.platform.startswith("linux")
                and userns_enabled == 1
                and maximum_user_namespaces > 0
            ),
        }

    def run(
        self,
        command: list[str],
        working_directory: str | None = None,
        timeout_seconds: float = 10,
        profile: NamespaceProfile | None = None,
    ) -> NamespaceRunResult:
        selected_profile = (
            profile
            or NamespaceProfile()
        )

        if not command:
            raise ValueError(
                "command must not be empty"
            )

        preflight = self.preflight()

        if not preflight["available"]:
            raise RuntimeError(
                "Linux namespaces are not available"
            )

        run_id = str(
            uuid.uuid4()
        )

        evidence_token = secrets.token_urlsafe(
            18
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

        host_namespaces = (
            self._namespace_links(
                "self"
            )
        )

        namespace_command = (
            self._build_command(
                command=command,
                evidence_token=evidence_token,
                hostname=hostname,
                profile=selected_profile,
            )
        )

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        start_time = time.monotonic()
        process = None
        stdout = ""
        stderr = ""
        exit_code = None
        timed_out = False
        failure_reason = None

        try:
            process = subprocess.Popen(
                namespace_command,
                cwd=resolved_working_directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

            try:
                stdout, stderr = (
                    process.communicate(
                        timeout=timeout_seconds
                    )
                )
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                failure_reason = (
                    "namespace_timeout_exceeded"
                )

                os.killpg(
                    process.pid,
                    signal.SIGKILL,
                )

                stdout, stderr = (
                    process.communicate()
                )
                exit_code = process.returncode

        except FileNotFoundError as exc:
            stderr = str(exc)
            failure_reason = (
                "namespace_launcher_not_found"
            )

        except PermissionError as exc:
            stderr = str(exc)
            failure_reason = (
                "namespace_launcher_permission_denied"
            )

        except Exception as exc:
            stderr = str(exc)
            failure_reason = (
                "namespace_launcher_error"
            )

        evidence, cleaned_stderr = (
            self._extract_evidence(
                stderr=stderr,
                token=evidence_token,
            )
        )

        namespace_checks = (
            self._namespace_checks(
                host_namespaces=host_namespaces,
                child_evidence=evidence,
                profile=selected_profile,
            )
        )

        no_new_privileges_enabled = bool(
            evidence.get(
                "no_new_privileges"
            )
        )

        capabilities_dropped = (
            self._capabilities_dropped(
                evidence
            )
        )

        network_isolated = bool(
            namespace_checks.get(
                "net",
                False,
            )
        )

        namespace_enabled = (
            bool(evidence)
            and evidence.get("pid") == 1
            and evidence.get("uid") == 0
            and no_new_privileges_enabled
            and capabilities_dropped
            and all(
                namespace_checks.values()
            )
        )

        if timed_out:
            status = "timed_out"
        elif (
            exit_code == 0
            and namespace_enabled
        ):
            status = "completed"
        elif (
            exit_code == 0
            and not evidence
        ):
            status = "failed"
            failure_reason = (
                "namespace_evidence_missing"
            )
        elif (
            exit_code == 0
            and not namespace_enabled
        ):
            status = "failed"
            failure_reason = (
                "namespace_validation_failed"
            )
        else:
            status = "failed"

            if failure_reason is None:
                failure_reason = (
                    "namespace_target_failed"
                )

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        result = NamespaceRunResult(
            run_id=run_id,
            command=command,
            namespace_command=(
                namespace_command
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
            failure_reason=failure_reason,
            exit_code=exit_code,
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(
                time.monotonic()
                - start_time,
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
            no_new_privileges_enabled=(
                no_new_privileges_enabled
            ),
            capabilities_dropped=(
                capabilities_dropped
            ),
            namespace_checks=(
                namespace_checks
            ),
            host_namespaces=(
                host_namespaces
            ),
            child_evidence=evidence,
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
        profile: NamespaceProfile,
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

        if profile.mount_proc:
            result.append(
                "--mount-proc"
            )

        if profile.network_isolation:
            result.append(
                "--net"
            )

        result.extend(
            [
                sys.executable,
                "-m",
                "app.sandbox.namespace_entrypoint",
                f"--evidence-token={evidence_token}",
                f"--hostname={hostname}",
                "--",
                *command,
            ]
        )

        return result

    def _namespace_checks(
        self,
        host_namespaces: dict[str, str | None],
        child_evidence: dict,
        profile: NamespaceProfile,
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
                child_namespaces.get(name)
                and host_namespaces.get(name)
                and child_namespaces.get(name)
                != host_namespaces.get(name)
            )
            for name in required
        }

    def _capabilities_dropped(
        self,
        evidence: dict,
    ) -> bool:
        status = evidence.get(
            "status",
            {},
        )

        fields = (
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
        )

        for field in fields:
            value = status.get(
                field
            )

            if value is None:
                return False

            try:
                if int(
                    str(value),
                    16,
                ) != 0:
                    return False
            except ValueError:
                return False

        return True

    def _extract_evidence(
        self,
        stderr: str,
        token: str,
    ) -> tuple[dict, str]:
        prefix = (
            "PROCSENTINEL_NAMESPACE_EVIDENCE"
            f"::{token}::"
        )

        evidence: dict = {}
        retained_lines: list[str] = []

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
                        "namespace_evidence_decode_failed"
                    )

                continue

            retained_lines.append(line)

        cleaned = "\n".join(
            retained_lines
        )

        if stderr.endswith("\n") and cleaned:
            cleaned += "\n"

        return evidence, cleaned

    def _namespace_links(
        self,
        process_id: str | int,
    ) -> dict[str, str | None]:
        values: dict[str, str | None] = {}

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
        result: NamespaceRunResult,
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
