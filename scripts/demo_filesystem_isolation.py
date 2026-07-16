import errno
import json
import os
from pathlib import Path


project_dir = Path(
    os.environ[
        "PROCSENTINEL_PROJECT_DIR"
    ]
)

workspace_dir = Path(
    os.environ[
        "PROCSENTINEL_WORKSPACE"
    ]
)

project_probe = (
    project_dir
    / ".procsentinel-project-write-probe"
)

workspace_probe = (
    workspace_dir
    / "workspace-write-probe.txt"
)

project_write_blocked = False
project_write_errno = None

try:
    project_probe.write_text(
        "unexpected-project-write",
        encoding="utf-8",
    )

    project_probe.unlink(
        missing_ok=True
    )
except OSError as exc:
    project_write_errno = (
        exc.errno
    )

    project_write_blocked = (
        exc.errno
        in {
            errno.EROFS,
            errno.EACCES,
            errno.EPERM,
        }
    )

workspace_probe.write_text(
    "workspace-write-ok",
    encoding="utf-8",
)

workspace_value = (
    workspace_probe.read_text(
        encoding="utf-8"
    )
)

print(
    json.dumps(
        {
            "project_dir": str(
                project_dir
            ),
            "workspace_dir": str(
                workspace_dir
            ),
            "project_readable": (
                project_dir.is_dir()
            ),
            "project_write_blocked": (
                project_write_blocked
            ),
            "project_write_errno": (
                project_write_errno
            ),
            "workspace_write_succeeded": (
                workspace_value
                == "workspace-write-ok"
            ),
            "workspace_file_exists": (
                workspace_probe.exists()
            ),
            "filesystem_isolated": (
                os.environ.get(
                    "PROCSENTINEL_FILESYSTEM_ISOLATED"
                )
                == "1"
            ),
        },
        ensure_ascii=False,
        sort_keys=True,
    ),
    flush=True,
)
