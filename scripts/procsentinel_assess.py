from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security.context import build_command_context
from app.security.decision import make_decision

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="data/workspaces/default")
    parser.add_argument("--role", default="regular_user")
    parser.add_argument("--policy", default="balanced")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.command and args.command[0] == "--":
        command = args.command[1:]
    else:
        command = args.command

    if not command:
        raise SystemExit("No command provided")

    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    context = build_command_context(
        command=command,
        working_directory=Path.cwd(),
        workspace_root=workspace,
        user_role=args.role,
        policy_name=args.policy,
    )

    decision = make_decision(context)

    output = {
        "command": command,
        "executable": context.executable,
        "user_role": context.user_role,
        "policy": context.policy_name,
        "workspace_root": str(context.workspace_root),
        "resolved_target_paths": [str(path) for path in context.resolved_target_paths],
        "is_destructive": context.is_destructive,
        "is_recursive": context.is_recursive,
        "is_force": context.is_force,
        "uses_shell": context.uses_shell,
        "has_workspace_target": context.has_workspace_target,
        "has_outside_workspace_target": context.has_outside_workspace_target,
        "has_sensitive_target": context.has_sensitive_target,
        "has_system_target": context.has_system_target,
        "unknown_target": context.unknown_target,
        "decision": decision.decision,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "execution_strategy": decision.execution_strategy,
        "requires_confirmation": decision.requires_confirmation,
        "can_execute": decision.can_execute,
        "risk_factors": [
            {
                "name": factor.name,
                "score": factor.score,
                "reason": factor.reason,
            }
            for factor in decision.risk_factors
        ],
        "reasons": decision.reasons,
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
