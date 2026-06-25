from pathlib import Path
import argparse
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security.audit import build_gateway_record, persist_gateway_record
from app.security.context import build_command_context
from app.security.decision import make_decision

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="data/workspaces/default")
    parser.add_argument("--role", default="regular_user")
    parser.add_argument("--policy", default="balanced")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()

def normalize_command(command):
    if command and command[0] == "--":
        return command[1:]

    return command

def print_analysis(command, context, decision):
    print("PROCSENTINEL_GATEWAY_ANALYSIS")
    print("Command:", shlex.join(command))
    print("Executable:", context.executable)
    print("User Role:", context.user_role)
    print("Policy:", context.policy_name)
    print("Workspace:", context.workspace_root)
    print("Decision:", decision.decision)
    print("Risk Score:", decision.risk_score)
    print("Risk Level:", decision.risk_level)
    print("Execution Strategy:", decision.execution_strategy)
    print("Requires Confirmation:", decision.requires_confirmation)
    print("Can Execute:", decision.can_execute)

    if context.resolved_target_paths:
        print("Resolved Target Paths:")
        for path in context.resolved_target_paths:
            print("-", path)

    if decision.risk_factors:
        print("Risk Breakdown:")
        for factor in decision.risk_factors:
            print(f"- {factor.name}: {factor.score} | {factor.reason}")

def run_allowed_command(command):
    pipeline_command = [
        sys.executable,
        str(ROOT / "scripts/run_security_command.py"),
        "--",
        *command,
    ]

    completed = subprocess.run(
        pipeline_command,
        cwd=str(ROOT),
        text=True,
    )

    return completed.returncode

def main():
    args = parse_args()
    command = normalize_command(args.command)

    if not command:
        print("COMMAND_REQUIRED")
        print("usage: python scripts/procsentinel_gateway.py -- <command>")
        return 2

    workspace = (ROOT / args.workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    context = build_command_context(
        command=command,
        working_directory=ROOT,
        workspace_root=workspace,
        user_role=args.role,
        policy_name=args.policy,
    )

    decision = make_decision(context)
    record = build_gateway_record(command, context, decision)
    persist_gateway_record(record, ROOT)

    print_analysis(command, context, decision)
    print("Gateway Decision ID:", record["gateway_decision_id"])
    print("Decision Status:", record["decision_status"])

    if not decision.can_execute:
        print("GATEWAY_ACTION: denied_before_execution")
        return 0

    if decision.requires_confirmation:
        print("GATEWAY_ACTION: pending_human_confirmation")
        print("Execution was not started.")
        return 0

    print("GATEWAY_ACTION: executing_inside_controlled_pipeline")
    return run_allowed_command(command)

if __name__ == "__main__":
    raise SystemExit(main())
