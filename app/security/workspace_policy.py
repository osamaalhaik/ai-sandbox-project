from dataclasses import dataclass
from pathlib import Path


CRITICAL_PATHS = (
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/root",
    "/sbin",
    "/sys",
    "/usr/bin",
    "/usr/sbin",
    "/var/lib",
)

SENSITIVE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh",
    "/root/.ssh",
    "/home/.ssh",
)


@dataclass(frozen=True)
class WorkspacePathAssessment:
    original_path: str
    resolved_path: str
    workspace_root: str
    classification: str
    allowed_for_destructive_action: bool
    requires_human_review: bool
    should_block: bool
    reason: str


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except RuntimeError:
        return path.absolute()


def _is_same_or_child(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _matches_protected_path(path: Path, protected_paths: tuple[str, ...]) -> bool:
    path_text = str(path)

    for protected in protected_paths:
        if path_text == protected:
            return True

        if protected != "/" and path_text.startswith(protected.rstrip("/") + "/"):
            return True

    return False


def assess_workspace_path(
    target_path: str,
    workspace_root: str = "data/workspaces/default",
) -> WorkspacePathAssessment:
    workspace = _safe_resolve(Path(workspace_root))
    target = Path(target_path)

    if not target.is_absolute():
        target = workspace / target

    resolved = _safe_resolve(target)

    if _matches_protected_path(resolved, SENSITIVE_PATHS):
        return WorkspacePathAssessment(
            original_path=target_path,
            resolved_path=str(resolved),
            workspace_root=str(workspace),
            classification="sensitive_path",
            allowed_for_destructive_action=False,
            requires_human_review=True,
            should_block=False,
            reason="Target path matches a sensitive security path and requires human review.",
        )

    if _matches_protected_path(resolved, CRITICAL_PATHS):
        return WorkspacePathAssessment(
            original_path=target_path,
            resolved_path=str(resolved),
            workspace_root=str(workspace),
            classification="critical_path",
            allowed_for_destructive_action=False,
            requires_human_review=False,
            should_block=True,
            reason="Target path matches a critical Linux system path and must be blocked before execution.",
        )

    if _is_same_or_child(resolved, workspace):
        return WorkspacePathAssessment(
            original_path=target_path,
            resolved_path=str(resolved),
            workspace_root=str(workspace),
            classification="inside_workspace",
            allowed_for_destructive_action=True,
            requires_human_review=False,
            should_block=False,
            reason="Target path is inside the controlled workspace boundary.",
        )

    return WorkspacePathAssessment(
        original_path=target_path,
        resolved_path=str(resolved),
        workspace_root=str(workspace),
        classification="outside_workspace",
        allowed_for_destructive_action=False,
        requires_human_review=True,
        should_block=False,
        reason="Target path is outside the controlled workspace boundary and requires human review.",
    )
