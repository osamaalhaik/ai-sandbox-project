from __future__ import annotations

import argparse
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--gate-fd",
        type=int,
        required=True,
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
            "Cgroup target command is required"
        )

    try:
        signal_value = os.read(
            args.gate_fd,
            1,
        )
    finally:
        os.close(
            args.gate_fd
        )

    if signal_value != b"1":
        raise SystemExit(
            "Cgroup launch gate was not released"
        )

    try:
        os.execvpe(
            command[0],
            command,
            os.environ.copy(),
        )
    except FileNotFoundError:
        print(
            "cgroup_target_not_found:"
            f"{command[0]}",
            file=sys.stderr,
            flush=True,
        )

        raise SystemExit(
            127
        )


if __name__ == "__main__":
    main()
