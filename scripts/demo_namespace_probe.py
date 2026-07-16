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
