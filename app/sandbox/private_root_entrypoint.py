from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

from app.sandbox.linux_security import (
    apply_no_new_privileges,
    capabilities_are_dropped,
    drop_all_capabilities,
    process_security_status,
    read_no_new_privileges,
)


NAMESPACE_NAMES = (
    "user",
    "mnt",
    "pid",
    "uts",
    "ipc",
    "net",
)


def run_mount(arguments: list[str]) -> None:
    result = subprocess.run(
        [
            "mount",
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "mount_failed:"
            + " ".join(arguments)
            + ":"
            + result.stderr.strip()
        )


def decode_mount_path(value: str) -> str:
    return (
        value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def mount_information(
    target: str | Path,
) -> dict:
    resolved = str(
        Path(target).resolve()
    )

    matches = []

    for line in Path(
        "/proc/self/mountinfo"
    ).read_text(
        encoding="utf-8"
    ).splitlines():
        parts = line.split()

        if "-" not in parts:
            continue

        separator = parts.index("-")

        if separator + 3 >= len(parts):
            continue

        mount_point = decode_mount_path(
            parts[4]
        )

        if mount_point != resolved:
            continue

        matches.append(
            {
                "mount_id": parts[0],
                "parent_id": parts[1],
                "root": decode_mount_path(
                    parts[3]
                ),
                "mount_point": mount_point,
                "mount_options": (
                    parts[5].split(",")
                ),
                "filesystem_type": (
                    parts[separator + 1]
                ),
                "source": decode_mount_path(
                    parts[separator + 2]
                ),
                "super_options": (
                    parts[
                        separator + 3
                    ].split(",")
                ),
            }
        )

    if not matches:
        return {}

    return matches[-1]


def copy_optional_file(
    source: str,
    destination: Path,
) -> None:
    source_path = Path(source)

    if not source_path.exists():
        return

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        source_path,
        destination,
    )


def copy_optional_tree(
    source: str,
    destination: Path,
) -> None:
    source_path = Path(source)

    if not source_path.is_dir():
        return

    shutil.copytree(
        source_path,
        destination,
        symlinks=True,
        dirs_exist_ok=True,
    )


def create_minimal_etc(
    root: Path,
    hostname: str,
) -> list[str]:
    etc = root / "etc"

    etc.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o755,
    )

    (etc / "passwd").write_text(
        (
            "root:x:0:0:"
            "ProcSentinel Sandbox:"
            "/workspace:"
            "/usr/sbin/nologin\n"
        ),
        encoding="utf-8",
    )

    (etc / "group").write_text(
        "root:x:0:\n",
        encoding="utf-8",
    )

    (etc / "nsswitch.conf").write_text(
        (
            "passwd: files\n"
            "group: files\n"
            "hosts: files dns\n"
        ),
        encoding="utf-8",
    )

    (etc / "hosts").write_text(
        (
            "127.0.0.1 localhost\n"
            "::1 localhost\n"
        ),
        encoding="utf-8",
    )

    (etc / "hostname").write_text(
        hostname + "\n",
        encoding="utf-8",
    )

    copy_optional_file(
        "/etc/ld.so.cache",
        etc / "ld.so.cache",
    )

    copy_optional_file(
        "/etc/ld.so.conf",
        etc / "ld.so.conf",
    )

    copy_optional_file(
        "/etc/localtime",
        etc / "localtime",
    )

    copy_optional_file(
        "/etc/timezone",
        etc / "timezone",
    )

    copy_optional_file(
        "/etc/ca-certificates.conf",
        etc / "ca-certificates.conf",
    )

    copy_optional_file(
        "/etc/ssl/openssl.cnf",
        etc / "ssl/openssl.cnf",
    )

    copy_optional_tree(
        "/etc/ld.so.conf.d",
        etc / "ld.so.conf.d",
    )

    copy_optional_tree(
        "/etc/ssl/certs",
        etc / "ssl/certs",
    )

    return sorted(
        item.name
        for item in etc.iterdir()
    )


def namespace_links() -> dict[str, str | None]:
    values = {}

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


def network_interfaces() -> list[str]:
    interfaces = []

    for line in Path(
        "/proc/net/dev"
    ).read_text(
        encoding="utf-8"
    ).splitlines()[2:]:
        if ":" not in line:
            continue

        name = line.split(
            ":",
            1,
        )[0].strip()

        if name:
            interfaces.append(name)

    return sorted(interfaces)


def proc_root_evidence() -> dict:
    try:
        return {
            "state": "readable",
            "value": os.path.realpath(
                "/proc/1/root"
            ),
            "errno": None,
        }
    except PermissionError as exc:
        return {
            "state": "denied",
            "value": None,
            "errno": exc.errno,
        }
    except OSError as exc:
        return {
            "state": "unavailable",
            "value": None,
            "errno": exc.errno,
        }


def setup_private_root(
    private_root_dir: str,
    project_dir: str,
    hostname: str,
    root_size_mb: int,
    workspace_size_mb: int,
    project_read_only: bool,
) -> dict:
    private_root = Path(
        private_root_dir
    ).resolve()

    project = Path(
        project_dir
    ).resolve()

    if not project.is_dir():
        raise RuntimeError(
            "project_directory_not_found:"
            f"{project}"
        )

    root_size = max(
        128,
        min(
            int(root_size_mb),
            1024,
        ),
    )

    workspace_size = max(
        8,
        min(
            int(workspace_size_mb),
            256,
        ),
    )

    private_root.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    run_mount(
        [
            "-t",
            "tmpfs",
            "-o",
            (
                f"size={root_size}m,"
                "mode=755,"
                "nosuid,"
                "nodev"
            ),
            "tmpfs",
            str(private_root),
        ]
    )

    project_target = (
        private_root
        / project.relative_to("/")
    )

    directories = [
        private_root / "usr",
        private_root / "etc",
        private_root / "proc",
        private_root / "dev",
        private_root / "tmp",
        private_root / "workspace",
        project_target,
    ]

    for directory in directories:
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    (private_root / "bin").symlink_to(
        "usr/bin"
    )

    (private_root / "lib").symlink_to(
        "usr/lib"
    )

    if Path(
        "/usr/lib64"
    ).is_dir():
        (
            private_root
            / "lib64"
        ).symlink_to(
            "usr/lib64"
        )

    run_mount(
        [
            "--rbind",
            "/usr",
            str(
                private_root
                / "usr"
            ),
        ]
    )

    run_mount(
        [
            "-o",
            "remount,bind,ro,nosuid,nodev",
            str(
                private_root
                / "usr"
            ),
        ]
    )

    minimal_etc_entries = create_minimal_etc(
        private_root,
        hostname,
    )

    run_mount(
        [
            "--bind",
            str(project),
            str(project_target),
        ]
    )

    if project_read_only:
        run_mount(
            [
                "-o",
                "remount,bind,ro,nosuid,nodev",
                str(project_target),
            ]
        )

    run_mount(
        [
            "-t",
            "proc",
            "-o",
            "nosuid,nodev,noexec",
            "proc",
            str(
                private_root
                / "proc"
            ),
        ]
    )

    run_mount(
        [
            "-t",
            "tmpfs",
            "-o",
            "mode=755,nosuid,noexec",
            "tmpfs",
            str(
                private_root
                / "dev"
            ),
        ]
    )

    for device in (
        "null",
        "zero",
        "random",
        "urandom",
    ):
        target = (
            private_root
            / "dev"
            / device
        )

        target.touch()

        run_mount(
            [
                "--bind",
                f"/dev/{device}",
                str(target),
            ]
        )

    run_mount(
        [
            "-t",
            "tmpfs",
            "-o",
            (
                "size=16m,"
                "mode=1777,"
                "nosuid,"
                "nodev,"
                "noexec"
            ),
            "tmpfs",
            str(
                private_root
                / "tmp"
            ),
        ]
    )

    run_mount(
        [
            "-t",
            "tmpfs",
            "-o",
            (
                f"size={workspace_size}m,"
                "mode=700,"
                "nosuid,"
                "nodev,"
                "noexec"
            ),
            "tmpfs",
            str(
                private_root
                / "workspace"
            ),
        ]
    )

    os.chroot(
        private_root
    )

    os.chdir(
        str(project)
    )

    root_mount = mount_information(
        "/"
    )

    project_mount = mount_information(
        project
    )

    workspace_mount = mount_information(
        "/workspace"
    )

    proc_mount = mount_information(
        "/proc"
    )

    dev_mount = mount_information(
        "/dev"
    )

    tmp_mount = mount_information(
        "/tmp"
    )

    workspace_options = set(
        workspace_mount.get(
            "mount_options",
            [],
        )
    ) | set(
        workspace_mount.get(
            "super_options",
            [],
        )
    )

    project_is_read_only = (
        "ro"
        in project_mount.get(
            "mount_options",
            [],
        )
    )

    workspace_restricted = {
        "nosuid",
        "nodev",
        "noexec",
    }.issubset(
        workspace_options
    )

    minimal_etc = (
        "passwd"
        in minimal_etc_entries
        and "group"
        in minimal_etc_entries
        and "nsswitch.conf"
        in minimal_etc_entries
        and "hosts"
        in minimal_etc_entries
        and "shadow"
        not in minimal_etc_entries
    )

    root_entries = sorted(
        item.name
        for item in Path("/").iterdir()
    )

    root_tmpfs = (
        root_mount.get(
            "filesystem_type"
        )
        == "tmpfs"
    )

    workspace_tmpfs = (
        workspace_mount.get(
            "filesystem_type"
        )
        == "tmpfs"
    )

    proc_mounted = (
        proc_mount.get(
            "filesystem_type"
        )
        == "proc"
    )

    private_root_enabled = (
        root_tmpfs
        and workspace_tmpfs
        and workspace_restricted
        and proc_mounted
        and minimal_etc
        and (
            not project_read_only
            or project_is_read_only
        )
        and not Path(
            "/host"
        ).exists()
    )

    return {
        "enabled": private_root_enabled,
        "root_tmpfs": root_tmpfs,
        "project_dir": str(project),
        "workspace_dir": "/workspace",
        "root_size_mb": root_size,
        "workspace_size_mb": (
            workspace_size
        ),
        "project_read_only": (
            project_is_read_only
            if project_read_only
            else False
        ),
        "workspace_tmpfs": (
            workspace_tmpfs
        ),
        "workspace_restricted": (
            workspace_restricted
        ),
        "proc_mounted": proc_mounted,
        "minimal_etc": minimal_etc,
        "minimal_etc_entries": (
            minimal_etc_entries
        ),
        "host_root_hidden": (
            not Path(
                "/host"
            ).exists()
        ),
        "root_entries": root_entries,
        "root_mount": root_mount,
        "project_mount": project_mount,
        "workspace_mount": (
            workspace_mount
        ),
        "proc_mount": proc_mount,
        "dev_mount": dev_mount,
        "tmp_mount": tmp_mount,
    }


def emit_evidence(
    token: str,
    private_root: dict,
) -> None:
    proc_root = proc_root_evidence()

    proc_root_private = (
        proc_root["state"]
        == "denied"
        or (
            proc_root["state"]
            == "readable"
            and proc_root["value"]
            == "/"
        )
    )

    status = process_security_status()

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
        "status": status,
        "capabilities_dropped": (
            capabilities_are_dropped(
                status
            )
        ),
        "no_new_privileges": (
            read_no_new_privileges()
        ),
        "proc_root": proc_root,
        "proc_root_private": (
            proc_root_private
        ),
        "private_root": private_root,
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
        "PROCSENTINEL_PRIVATE_ROOT_EVIDENCE"
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
        "--private-root-dir",
        required=True,
    )

    parser.add_argument(
        "--root-size-mb",
        type=int,
        default=256,
    )

    parser.add_argument(
        "--workspace-size-mb",
        type=int,
        default=32,
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
        and command[0]
        == "--"
    ):
        command = command[1:]

    if not command:
        raise SystemExit(
            "Private-root target command is required"
        )

    os.umask(
        0o077
    )

    socket.sethostname(
        args.hostname.encode(
            "utf-8"
        )
    )

    private_root = setup_private_root(
        private_root_dir=(
            args.private_root_dir
        ),
        project_dir=(
            args.project_dir
        ),
        hostname=(
            args.hostname
        ),
        root_size_mb=(
            args.root_size_mb
        ),
        workspace_size_mb=(
            args.workspace_size_mb
        ),
        project_read_only=(
            args.project_read_only
            == "true"
        ),
    )

    drop_all_capabilities()
    apply_no_new_privileges()

    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": (
            private_root[
                "project_dir"
            ]
        ),
        "HOME": "/workspace",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PROCSENTINEL_PRIVATE_ROOT_ACTIVE": (
            "1"
        ),
        "PROCSENTINEL_PROJECT_DIR": (
            private_root[
                "project_dir"
            ]
        ),
        "PROCSENTINEL_WORKSPACE": (
            private_root[
                "workspace_dir"
            ]
        ),
    }

    emit_evidence(
        args.evidence_token,
        private_root,
    )

    try:
        os.execvpe(
            command[0],
            command,
            environment,
        )
    except FileNotFoundError:
        print(
            "private_root_target_not_found:"
            f"{command[0]}",
            file=os.sys.stderr,
            flush=True,
        )

        raise SystemExit(
            127
        )


if __name__ == "__main__":
    main()
