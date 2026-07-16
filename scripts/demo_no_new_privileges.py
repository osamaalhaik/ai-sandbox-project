from pathlib import Path


def read_no_new_privileges() -> bool:
    status_path = Path("/proc/self/status")

    for line in status_path.read_text(
        encoding="utf-8"
    ).splitlines():
        if line.startswith("NoNewPrivs:"):
            return (
                line.split(":", 1)[1].strip()
                == "1"
            )

    raise RuntimeError(
        "NoNewPrivs field was not found"
    )


enabled = read_no_new_privileges()

print(
    f"NoNewPrivs={int(enabled)}",
    flush=True,
)

if not enabled:
    raise SystemExit(4)
