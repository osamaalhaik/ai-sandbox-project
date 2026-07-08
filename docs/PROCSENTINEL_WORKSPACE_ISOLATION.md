# ProcSentinel AI - Workspace Isolation and Path Enforcement

## Overview

The Workspace Isolation layer defines a clear boundary between safe project-controlled paths and paths that require review or blocking.

This improves the project security model because destructive commands are not judged only by executable name, but also by the target path and its relation to the controlled workspace.

## Classifications

| Classification | Meaning | Decision |
|---|---|---|
| inside_workspace | Target is inside the controlled workspace | Can be allowed with monitoring |
| outside_workspace | Target escapes the workspace boundary | Requires human review |
| sensitive_path | Target matches sensitive security files or directories | Requires human review |
| critical_path | Target matches critical Linux system paths | Must be blocked |

## Default Workspace

data/workspaces/default

## Demo Command

python scripts/procsentinel_workspace_demo.py

## Example Behavior

cache -> inside_workspace  
../outside-cache -> outside_workspace  
/etc/passwd -> sensitive_path  
/etc -> critical_path

## Academic Value

This layer strengthens ProcSentinel AI as a graduation-style project by showing a clear security boundary model.

It demonstrates:

- Path normalization
- Workspace boundary checking
- Sensitive path classification
- Critical path blocking
- Explainable security decisions

## Validation Status

Expected current result after this stage:

Ran 80 tests
OK

## Future Work

- Integrate workspace policy more deeply into the Gateway decision engine
- Add configurable workspace profiles
- Add per-user workspaces
- Add filesystem-level isolation using namespaces, chroot, Landlock, or containers
