import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.security.workspace_policy import assess_workspace_path


DEFAULT_PATHS = [
    "cache",
    "logs/run.log",
    "../outside-cache",
    "/tmp/procsentinel-demo",
    "/etc/passwd",
    "/etc",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="data/workspaces/default")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    paths = args.paths or DEFAULT_PATHS

    print("PROCSENTINEL_WORKSPACE_ISOLATION_DEMO")
    print(f"workspace={args.workspace}")
    print("-" * 80)

    for path in paths:
        assessment = assess_workspace_path(path, args.workspace)
        print(f"path={assessment.original_path}")
        print(f"resolved={assessment.resolved_path}")
        print(f"classification={assessment.classification}")
        print(f"allowed_for_destructive_action={assessment.allowed_for_destructive_action}")
        print(f"requires_human_review={assessment.requires_human_review}")
        print(f"should_block={assessment.should_block}")
        print(f"reason={assessment.reason}")
        print("-" * 80)


if __name__ == "__main__":
    main()
