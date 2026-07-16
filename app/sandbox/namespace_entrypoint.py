from __future__ import annotations

import argparse
import base64
import json
import os
import socket
from pathlib import Path

from app.sandbox.filesystem_isolation import (
    setup_filesystem_isolation,
)
from app.sandbox.linux_security import (
    apply_no_new_privileges,
    drop_all_capabilities,
    read_no_new_privileges,
)


NAMESPACE_NAMES = (
    "user",
    "mnt",
    "pid",
    "uts",
    "ipc",
    "net",
    "cgroup",
)


def namespace_links() -> dict[str, str | None]:
    values: dict[str, str | None] = {}

    for name in NAMESPACE_NAMES:
        path = Path(
            f"/proc/self/ns/{name}"
        )

        try:
            values[name] = os.readlink(
                path
            )
        except OSError:
            values[name] = None

    return values


def status_values() -> dict[str, str]:
    requested = {
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    }

    values: dict[str, str] = {}

    for line in Path(
        "/proc/self/status"
    ).read_text(
        encoding="utf-8"
    ).splitlines():
        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        if key in requested:
            values[key] = value.strip()

    return values


def network_interfaces() -> list[str]:
    lines = Path(
        "/proc/net/dev"
    ).read_text(
        encoding="utf-8"
    ).splitlines()[2:]

    interfaces = []

    for line in lines:
        if ":" not in line:
            continue

        name = line.split(
            ":",
            1,
        )[0].strip()

        if name:
            interfaces.append(name)

    return sorted(
        interfaces
    )


def emit_evidence(
    token: str,
    filesystem: dict,
) -> None:
    evidence = {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "hostname": socket.gethostname(),
        "namespaces": namespace_links(),
        "network_interfaces": (
            network_interfaces()
        ),
        "status": status_values(),
        "no_new_privileges": (
            read_no_new_privileges()
        ),
        "filesystem": filesystem,
    }

    encoded = base64.urlsafe_b64encode(
        json.dumps(
            evidence,
            ensure_ascii=False,
            sort_keys=True,
        ).encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    )

    print(
        "PROCSENTINEL_NAMESPACE_EVIDENCE"
        f"::{token}::{encoded}",
        file=os.sys.stderr,
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--evidence-token",
        required=True,
    )

    parser.add_argument(
        "--hostname",
        required=True,
    )

    parser.add_argument(
        "--project-dir",
        required=True,
    )

    parser.add_argument(
        "--workspace-dir",
        required=True,
    )

    parser.add_argument(
        "--workspace-size-mb",
        type=int,
        default=16,
    )

    parser.add_argument(
        "--filesystem-isolation",
        choices=(
            "true",
            "false",
        ),
        default="true",
    )

    parser.add_argument(
        "--project-read-only",
        choices=(
            "true",
            "false",
        ),
        default="true",
    )

    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
    )

    args = parser.parse_args()

    command = list(
        args.command
    )

    if (
        command
        and command[0] == "--"
    ):
        command = command[1:]

    if not command:
        raise SystemExit(
            "Namespace target command is required"
        )

    os.umask(
        0o077
    )

    socket.sethostname(
        args.hostname.encode(
            "utf-8"
        )
    )

    filesystem = {
        "enabled": False,
        "project_dir": str(
            Path(
                args.project_dir
            ).resolve()
        ),
        "workspace_dir": str(
            Path(
                args.workspace_dir
            ).resolve()
        ),
        "workspace_size_mb": (
            args.workspace_size_mb
        ),
        "project_read_only": False,
        "workspace_tmpfs": False,
        "workspace_restricted": False,
        "project_mount": {},
        "workspace_mount": {},
    }

    if (
        args.filesystem_isolation
        == "true"
    ):
        filesystem = (
            setup_filesystem_isolation(
                project_dir=(
                    args.project_dir
                ),
                workspace_dir=(
                    args.workspace_dir
                ),
                workspace_size_mb=(
                    args.workspace_size_mb
                ),
                project_read_only=(
                    args.project_read_only
                    == "true"
                ),
            )
        )

    drop_all_capabilities()
    apply_no_new_privileges()

    os.environ[
        "PROCSENTINEL_NAMESPACE_ACTIVE"
    ] = "1"

    os.environ[
        "PROCSENTINEL_PROJECT_DIR"
    ] = filesystem[
        "project_dir"
    ]

    os.environ[
        "PROCSENTINEL_WORKSPACE"
    ] = filesystem[
        "workspace_dir"
    ]

    os.environ[
        "PROCSENTINEL_FILESYSTEM_ISOLATED"
    ] = (
        "1"
        if filesystem.get(
            "enabled"
        )
        else "0"
    )

    emit_evidence(
        args.evidence_token,
        filesystem,
    )

    try:
        os.execvpe(
            command[0],
            command,
            os.environ.copy(),
        )
    except FileNotFoundError:
        print(
            "namespace_target_not_found:"
            f"{command[0]}",
            file=os.sys.stderr,
            flush=True,
        )

        raise SystemExit(
            127
        )


if __name__ == "__main__":
    main()
