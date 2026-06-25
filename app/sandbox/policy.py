from dataclasses import dataclass
from pathlib import Path

from app.security.context import DESTRUCTIVE_EXECUTABLES, build_command_context
from app.security.decision import make_decision


@dataclass
class CommandPolicyDecision:
    allowed: bool
    reason: str | None
    executable: str | None
    security_decision: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    execution_strategy: str | None = None
    requires_confirmation: bool = False


class SandboxCommandPolicy:
    def __init__(self):
        self.allowed_executables = {
            "echo",
            "sleep",
            "true",
            "false",
            "date",
            "whoami",
            "pwd",
            "ls",
            "cat",
            "python",
            "python3",
        }

        self.blocked_executables = {
            "dd",
            "mkfs",
            "mkfs.ext4",
            "shutdown",
            "reboot",
            "poweroff",
            "halt",
            "mount",
            "umount",
            "chmod",
            "chown",
            "sudo",
            "su",
            "bash",
            "sh",
            "zsh",
            "curl",
            "wget",
            "nc",
            "netcat",
            "ssh",
            "scp",
            "rsync",
        }

    def validate(self, command: list[str], working_directory: str) -> CommandPolicyDecision:
        if not command:
            return CommandPolicyDecision(False, "empty_command", None)

        executable = Path(command[0]).name

        if executable in DESTRUCTIVE_EXECUTABLES:
            return self._validate_context_aware_command(command, working_directory, executable)

        if executable in self.blocked_executables:
            return CommandPolicyDecision(False, "blocked_executable", executable)

        if executable not in self.allowed_executables:
            return CommandPolicyDecision(False, "executable_not_allowed", executable)

        if executable in {"python", "python3"}:
            return self._validate_python_command(command, working_directory, executable)

        if executable == "sleep":
            return self._validate_sleep_command(command, executable)

        if executable in {"cat", "ls"}:
            return self._validate_file_command(command, working_directory, executable)

        return CommandPolicyDecision(True, "command_allowed", executable)

    def _validate_context_aware_command(
        self,
        command: list[str],
        working_directory: str,
        executable: str,
    ) -> CommandPolicyDecision:
        base_dir = Path(working_directory).resolve()
        workspace_root = (base_dir / "data" / "workspaces" / "default").resolve()
        workspace_root.mkdir(parents=True, exist_ok=True)

        context = build_command_context(
            command=command,
            working_directory=base_dir,
            workspace_root=workspace_root,
            user_role="regular_user",
            policy_name="balanced",
        )

        decision = make_decision(context)

        if not decision.can_execute:
            return CommandPolicyDecision(
                allowed=False,
                reason=f"context_decision_{decision.decision}",
                executable=executable,
                security_decision=decision.decision,
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                execution_strategy=decision.execution_strategy,
                requires_confirmation=decision.requires_confirmation,
            )

        if decision.requires_confirmation:
            return CommandPolicyDecision(
                allowed=False,
                reason="confirmation_required",
                executable=executable,
                security_decision=decision.decision,
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                execution_strategy=decision.execution_strategy,
                requires_confirmation=True,
            )

        return CommandPolicyDecision(
            allowed=True,
            reason=f"context_decision_{decision.decision}",
            executable=executable,
            security_decision=decision.decision,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            execution_strategy=decision.execution_strategy,
            requires_confirmation=False,
        )

    def _validate_python_command(
        self,
        command: list[str],
        working_directory: str,
        executable: str,
    ) -> CommandPolicyDecision:
        if len(command) < 2:
            return CommandPolicyDecision(False, "python_script_required", executable)

        script_arg = command[1]

        if script_arg in {"-c", "-m"} or script_arg.startswith("-"):
            return CommandPolicyDecision(False, "unsafe_python_mode", executable)

        base_dir = Path(working_directory).resolve()
        script_path = Path(script_arg)

        if script_path.is_absolute():
            resolved_script = script_path.resolve()
        else:
            resolved_script = (base_dir / script_path).resolve()

        allowed_dirs = [
            (base_dir / "scripts").resolve(),
            (base_dir / "tests").resolve(),
        ]

        if resolved_script.suffix != ".py":
            return CommandPolicyDecision(False, "python_target_not_python_file", executable)

        if not any(self._is_inside(resolved_script, allowed_dir) for allowed_dir in allowed_dirs):
            return CommandPolicyDecision(False, "python_script_outside_allowed_dirs", executable)

        return CommandPolicyDecision(True, "command_allowed", executable)

    def _validate_sleep_command(
        self,
        command: list[str],
        executable: str,
    ) -> CommandPolicyDecision:
        if len(command) != 2:
            return CommandPolicyDecision(False, "invalid_sleep_arguments", executable)

        try:
            value = float(command[1])
        except ValueError:
            return CommandPolicyDecision(False, "invalid_sleep_duration", executable)

        if value < 0 or value > 60:
            return CommandPolicyDecision(False, "sleep_duration_out_of_range", executable)

        return CommandPolicyDecision(True, "command_allowed", executable)

    def _validate_file_command(
        self,
        command: list[str],
        working_directory: str,
        executable: str,
    ) -> CommandPolicyDecision:
        base_dir = Path(working_directory).resolve()

        if executable == "cat" and len(command) < 2:
            return CommandPolicyDecision(False, "file_argument_required", executable)

        for item in command[1:]:
            if item.startswith("-"):
                continue

            path = Path(item)

            if path.is_absolute():
                resolved_path = path.resolve()
            else:
                resolved_path = (base_dir / path).resolve()

            if not self._is_inside(resolved_path, base_dir):
                return CommandPolicyDecision(False, "path_outside_working_directory", executable)

        return CommandPolicyDecision(True, "command_allowed", executable)

    def _is_inside(self, path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False
