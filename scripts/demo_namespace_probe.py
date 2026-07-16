import json
import os
import socket
from pathlib import Path


def namespace_links():
    values = {}

    for name in (
        "user",
        "mnt",
        "pid",
        "uts",
        "ipc",
        "net",
    ):
        values[name] = os.readlink(
            f"/proc/self/ns/{name}"
        )

    return values


def no_new_privileges():
    for line in Path(
        "/proc/self/status"
    ).read_text(
        encoding="utf-8"
    ).splitlines():
        if line.startswith(
            "NoNewPrivs:"
        ):
            return (
                line.split(
                    ":",
                    1,
                )[1].strip()
                == "1"
            )

    return False


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
    fields = (
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
    )

    return all(
        field in status
        and int(
            status[field],
            16,
        )
        == 0
        for field in fields
    )


def interfaces():
    values = []

    for line in Path(
        "/proc/net/dev"
    ).read_text(
        encoding="utf-8"
    ).splitlines()[2:]:
        if ":" in line:
            values.append(
                line.split(
                    ":",
                    1,
                )[0].strip()
            )

    return sorted(values)


status = security_status()

print(
    json.dumps(
        {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "uid": os.getuid(),
            "hostname": socket.gethostname(),
            "no_new_privileges": (
                no_new_privileges()
            ),
            "capabilities_dropped": (
                capabilities_dropped(
                    status
                )
            ),
            "status": status,
            "namespaces": namespace_links(),
            "network_interfaces": interfaces(),
            "namespace_active": (
                os.getenv(
                    "PROCSENTINEL_NAMESPACE_ACTIVE"
                )
            ),
        },
        ensure_ascii=False,
        sort_keys=True,
    ),
    flush=True,
)
