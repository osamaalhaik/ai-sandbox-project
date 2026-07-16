from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path


PR_SET_NO_NEW_PRIVS = 38


def apply_no_new_privileges() -> None:
    if os.name != "posix":
        raise RuntimeError(
            "NoNewPrivileges requires a POSIX Linux environment"
        )

    libc = ctypes.CDLL(
        None,
        use_errno=True,
    )

    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int

    result = prctl(
        PR_SET_NO_NEW_PRIVS,
        1,
        0,
        0,
        0,
    )

    if result != 0:
        error_number = ctypes.get_errno()

        raise OSError(
            error_number,
            os.strerror(
                error_number
                or errno.EPERM
            ),
        )


def read_no_new_privileges(
    pid: int | None = None,
) -> bool:
    process_id = (
        pid
        if pid is not None
        else "self"
    )

    status_path = Path(
        f"/proc/{process_id}/status"
    )

    for line in status_path.read_text(
        encoding="utf-8"
    ).splitlines():
        if line.startswith(
            "NoNewPrivs:"
        ):
            value = line.split(
                ":",
                1,
            )[1].strip()

            return value == "1"

    raise RuntimeError(
        "NoNewPrivs field was not found"
    )
