from pathlib import Path
from .models import CommandContext

DESTRUCTIVE_EXECUTABLES = {
    "rm",
    "unlink",
    "rmdir",
    "shred",
}

SHELL_EXECUTABLES = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
}

SENSITIVE_PATHS = [
    "/etc",
    "/root",
    "/boot",
    "/var/log",
    "/var/lib",
    "/var/run",
]

CRITICAL_SYSTEM_PATHS = [
    "/",
    "/etc",
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib64",
    "/boot",
    "/root",
    "/proc",
    "/sys",
    "/dev",
]

def normalize_executable(command: list[str]) -> str:
    if not command:
        return ""

    return Path(command[0]).name

def has_recursive_flag(command: list[str]) -> bool:
    flags = "".join(part for part in command[1:] if part.startswith("-"))
    return "r" in flags or "R" in flags or "--recursive" in command

def has_force_flag(command: list[str]) -> bool:
    flags = "".join(part for part in command[1:] if part.startswith("-"))
    return "f" in flags or "--force" in command

def extract_target_paths(command: list[str], executable: str) -> list[Path]:
    if executable not in DESTRUCTIVE_EXECUTABLES:
        return []

    targets = []

    for part in command[1:]:
        if part.startswith("-"):
            continue

        targets.append(Path(part))

    return targets

def resolve_path(path: Path, working_directory: Path) -> Path:
    if path.is_absolute():
        return path.resolve(strict=False)

    return (working_directory / path).resolve(strict=False)

def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False

def protected_path_matches(path: Path, protected: str) -> bool:
    protected_path = Path(protected)

    if protected == "/":
        return path == protected_path

    if path == protected_path:
        return True

    try:
        path.relative_to(protected_path)
        return True
    except ValueError:
        return False

def matches_any(path: Path, protected_paths: list[str]) -> bool:
    return any(protected_path_matches(path, protected) for protected in protected_paths)

def build_command_context(
    command: list[str],
    working_directory: str | Path,
    workspace_root: str | Path,
    user_role: str = "regular_user",
    policy_name: str = "balanced",
) -> CommandContext:
    working_directory_path = Path(working_directory).resolve(strict=False)
    workspace_root_path = Path(workspace_root).resolve(strict=False)
    executable = normalize_executable(command)

    target_paths = extract_target_paths(command, executable)
    resolved_target_paths = [
        resolve_path(path, working_directory_path)
        for path in target_paths
    ]

    is_destructive = executable in DESTRUCTIVE_EXECUTABLES
    is_recursive = has_recursive_flag(command)
    is_force = has_force_flag(command)
    uses_shell = executable in SHELL_EXECUTABLES

    outside_workspace_paths = [
        path for path in resolved_target_paths
        if not is_relative_to(path, workspace_root_path)
    ]

    workspace_paths = [
        path for path in resolved_target_paths
        if is_relative_to(path, workspace_root_path)
    ]

    has_sensitive_target = any(
        matches_any(path, SENSITIVE_PATHS)
        for path in outside_workspace_paths
    )

    has_system_target = any(
        matches_any(path, CRITICAL_SYSTEM_PATHS)
        for path in outside_workspace_paths
    )

    has_outside_workspace_target = bool(outside_workspace_paths)
    has_workspace_target = bool(resolved_target_paths) and len(workspace_paths) == len(resolved_target_paths)
    unknown_target = is_destructive and not resolved_target_paths

    return CommandContext(
        command=command,
        executable=executable,
        working_directory=working_directory_path,
        workspace_root=workspace_root_path,
        target_paths=target_paths,
        resolved_target_paths=resolved_target_paths,
        is_destructive=is_destructive,
        is_recursive=is_recursive,
        is_force=is_force,
        uses_shell=uses_shell,
        has_sensitive_target=has_sensitive_target,
        has_system_target=has_system_target,
        has_outside_workspace_target=has_outside_workspace_target,
        has_workspace_target=has_workspace_target,
        unknown_target=unknown_target,
        user_role=user_role,
        policy_name=policy_name,
    )
