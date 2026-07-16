from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class FilesystemIsolationEvidence:
    enabled: bool
    project_dir: str
    workspace_dir: str
    workspace_size_mb: int
    project_read_only: bool
    workspace_tmpfs: bool
    workspace_restricted: bool
    project_mount: dict
    workspace_mount: dict


def _run_mount(
    arguments: list[str],
) -> None:
    process = subprocess.run(
        [
            "mount",
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if process.returncode != 0:
        raise RuntimeError(
            "mount_failed:"
            + " ".join(arguments)
            + ":"
            + process.stderr.strip()
        )


def _decode_mount_path(
    value: str,
) -> str:
    return (
        value.replace(
            "\\040",
            " ",
        )
        .replace(
            "\\011",
            "\t",
        )
        .replace(
            "\\012",
            "\n",
        )
        .replace(
            "\\134",
            "\\",
        )
    )


def mount_information(
    target: str | Path,
) -> dict:
    resolved_target = str(
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

        mount_point = _decode_mount_path(
            parts[4]
        )

        if mount_point != resolved_target:
            continue

        matches.append(
            {
                "mount_id": parts[0],
                "parent_id": parts[1],
                "root": _decode_mount_path(
                    parts[3]
                ),
                "mount_point": mount_point,
                "mount_options": (
                    parts[5].split(",")
                ),
                "filesystem_type": (
                    parts[separator + 1]
                ),
                "source": _decode_mount_path(
                    parts[separator + 2]
                ),
                "super_options": (
                    parts[separator + 3].split(
                        ","
                    )
                ),
            }
        )

    if not matches:
        return {}

    return matches[-1]


def setup_filesystem_isolation(
    project_dir: str,
    workspace_dir: str,
    workspace_size_mb: int,
    project_read_only: bool,
) -> dict:
    project = Path(
        project_dir
    ).resolve()

    workspace = Path(
        workspace_dir
    ).resolve()

    if not project.is_dir():
        raise RuntimeError(
            "project_directory_not_found:"
            f"{project}"
        )

    workspace.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    size = max(
        4,
        min(
            int(workspace_size_mb),
            256,
        ),
    )

    _run_mount(
        [
            "-t",
            "tmpfs",
            "-o",
            (
                f"size={size}m,"
                "mode=700,"
                "nosuid,"
                "nodev,"
                "noexec"
            ),
            "tmpfs",
            str(workspace),
        ]
    )

    if project_read_only:
        _run_mount(
            [
                "--bind",
                str(project),
                str(project),
            ]
        )

        _run_mount(
            [
                "-o",
                "remount,bind,ro",
                str(project),
            ]
        )

    workspace_mount = mount_information(
        workspace
    )

    project_mount = mount_information(
        project
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

    workspace_tmpfs = (
        workspace_mount.get(
            "filesystem_type"
        )
        == "tmpfs"
    )

    workspace_restricted = {
        "nosuid",
        "nodev",
        "noexec",
    }.issubset(
        workspace_options
    )

    project_is_read_only = (
        "ro"
        in project_mount.get(
            "mount_options",
            [],
        )
    )

    enabled = (
        workspace_tmpfs
        and workspace_restricted
        and (
            not project_read_only
            or project_is_read_only
        )
    )

    evidence = FilesystemIsolationEvidence(
        enabled=enabled,
        project_dir=str(project),
        workspace_dir=str(workspace),
        workspace_size_mb=size,
        project_read_only=(
            project_is_read_only
            if project_read_only
            else False
        ),
        workspace_tmpfs=(
            workspace_tmpfs
        ),
        workspace_restricted=(
            workspace_restricted
        ),
        project_mount=project_mount,
        workspace_mount=workspace_mount,
    )

    return asdict(
        evidence
    )
