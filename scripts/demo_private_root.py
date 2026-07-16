import errno
import json
import os
from pathlib import Path


def security_status():
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

    values = {}

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


def capabilities_dropped(status):
    return all(
        int(
            status[field],
            16,
        )
        == 0
        for field in (
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
        )
    )


def network_interfaces():
    values = []

    for line in Path(
        "/proc/net/dev"
    ).read_text(
        encoding="utf-8"
    ).splitlines()[2:]:
        if ":" not in line:
            continue

        values.append(
            line.split(
                ":",
                1,
            )[0].strip()
        )

    return sorted(values)


def proc_root_evidence():
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


project = Path(
    os.environ[
        "PROCSENTINEL_PROJECT_DIR"
    ]
)

workspace = Path(
    os.environ[
        "PROCSENTINEL_WORKSPACE"
    ]
)

workspace_probe = (
    workspace
    / "private-root-target.txt"
)

workspace_probe.write_text(
    "private-root-target-ok",
    encoding="utf-8",
)

project_probe = (
    project
    / ".private-root-target-write"
)

project_write_blocked = False
project_write_errno = None

try:
    project_probe.write_text(
        "unexpected-write",
        encoding="utf-8",
    )

    project_probe.unlink(
        missing_ok=True
    )

except OSError as exc:
    project_write_errno = exc.errno

    project_write_blocked = (
        exc.errno
        in {
            errno.EROFS,
            errno.EACCES,
            errno.EPERM,
        }
    )

status = security_status()
proc_root = proc_root_evidence()

result = {
    "pid": os.getpid(),
    "ppid": os.getppid(),
    "uid": os.getuid(),
    "gid": os.getgid(),
    "private_root_active": (
        os.environ.get(
            "PROCSENTINEL_PRIVATE_ROOT_ACTIVE"
        )
        == "1"
    ),
    "root_entries": sorted(
        item.name
        for item in Path("/").iterdir()
    ),
    "etc_entries": sorted(
        item.name
        for item in Path(
            "/etc"
        ).iterdir()
    ),
    "shadow_present": (
        Path(
            "/etc/shadow"
        ).exists()
    ),
    "host_root_alias_present": (
        Path("/host").exists()
    ),
    "project_readable": (
        project.is_dir()
    ),
    "project_write_blocked": (
        project_write_blocked
    ),
    "project_write_errno": (
        project_write_errno
    ),
    "workspace_write_succeeded": (
        workspace_probe.read_text(
            encoding="utf-8"
        )
        == "private-root-target-ok"
    ),
    "network_interfaces": (
        network_interfaces()
    ),
    "status": status,
    "capabilities_dropped": (
        capabilities_dropped(
            status
        )
    ),
    "no_new_privileges": (
        status.get(
            "NoNewPrivs"
        )
        == "1"
    ),
    "proc_root": proc_root,
    "proc_root_private": (
        proc_root["state"]
        == "denied"
        or (
            proc_root["state"]
            == "readable"
            and proc_root["value"]
            == "/"
        )
    ),
}

print(
    json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
    ),
    flush=True,
)
