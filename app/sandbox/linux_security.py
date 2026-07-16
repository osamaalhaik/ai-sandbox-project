from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path


PR_CAPBSET_DROP = 24
PR_SET_SECUREBITS = 28
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4

SECBIT_NOROOT = 1 << 0
SECBIT_NOROOT_LOCKED = 1 << 1
SECBIT_NO_SETUID_FIXUP = 1 << 2
SECBIT_NO_SETUID_FIXUP_LOCKED = 1 << 3
SECBIT_NO_CAP_AMBIENT_RAISE = 1 << 6
SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED = 1 << 7

LINUX_CAPABILITY_VERSION_3 = 0x20080522

CAPABILITY_FIELDS = (
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
)


class CapabilityHeader(ctypes.Structure):
    _fields_ = [
        (
            "version",
            ctypes.c_uint32,
        ),
        (
            "pid",
            ctypes.c_int,
        ),
    ]


class CapabilityData(ctypes.Structure):
    _fields_ = [
        (
            "effective",
            ctypes.c_uint32,
        ),
        (
            "permitted",
            ctypes.c_uint32,
        ),
        (
            "inheritable",
            ctypes.c_uint32,
        ),
    ]


def _libc():
    return ctypes.CDLL(
        None,
        use_errno=True,
    )


def _raise_os_error() -> None:
    error_number = (
        ctypes.get_errno()
        or errno.EPERM
    )

    raise OSError(
        error_number,
        os.strerror(
            error_number
        ),
    )


def _prctl(
    option: int,
    argument_2: int = 0,
    argument_3: int = 0,
    argument_4: int = 0,
    argument_5: int = 0,
) -> None:
    libc = _libc()

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
        option,
        argument_2,
        argument_3,
        argument_4,
        argument_5,
    )

    if result != 0:
        _raise_os_error()


def apply_no_new_privileges() -> None:
    if os.name != "posix":
        raise RuntimeError(
            "NoNewPrivileges requires Linux"
        )

    _prctl(
        PR_SET_NO_NEW_PRIVS,
        1,
    )


def capability_last_value() -> int:
    path = Path(
        "/proc/sys/kernel/cap_last_cap"
    )

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
        return 40


def drop_all_capabilities() -> None:
    if os.name != "posix":
        raise RuntimeError(
            "Capability controls require Linux"
        )

    securebits = (
        SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED
        | SECBIT_NO_CAP_AMBIENT_RAISE
        | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED
    )

    _prctl(
        PR_SET_SECUREBITS,
        securebits,
    )

    try:
        _prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL,
        )
    except OSError as exc:
        if exc.errno not in {
            errno.EINVAL,
            errno.ENOSYS,
        }:
            raise

    for capability in range(
        capability_last_value() + 1
    ):
        try:
            _prctl(
                PR_CAPBSET_DROP,
                capability,
            )
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise

    libc = _libc()

    capset = libc.capset
    capset.argtypes = [
        ctypes.POINTER(
            CapabilityHeader
        ),
        ctypes.POINTER(
            CapabilityData
        ),
    ]
    capset.restype = ctypes.c_int

    header = CapabilityHeader(
        version=(
            LINUX_CAPABILITY_VERSION_3
        ),
        pid=0,
    )

    data = (
        CapabilityData
        * 2
    )()

    result = capset(
        ctypes.byref(header),
        data,
    )

    if result != 0:
        _raise_os_error()


def process_security_status(
    pid: int | None = None,
) -> dict[str, str]:
    process_id = (
        str(pid)
        if pid is not None
        else "self"
    )

    status_path = Path(
        f"/proc/{process_id}/status"
    )

    requested = {
        *CAPABILITY_FIELDS,
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    }

    values: dict[str, str] = {}

    for line in status_path.read_text(
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


def capabilities_are_dropped(
    status: dict[str, str] | None = None,
) -> bool:
    values = (
        status
        if status is not None
        else process_security_status()
    )

    for field in CAPABILITY_FIELDS:
        value = values.get(
            field
        )

        if value is None:
            return False

        try:
            if int(
                value,
                16,
            ) != 0:
                return False
        except ValueError:
            return False

    return True


def read_no_new_privileges(
    pid: int | None = None,
) -> bool:
    status = process_security_status(
        pid
    )

    return (
        status.get(
            "NoNewPrivs"
        )
        == "1"
    )
