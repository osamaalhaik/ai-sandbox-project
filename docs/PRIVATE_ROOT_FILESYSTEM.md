# Private Root Filesystem

ProcSentinel AI provides an independent private-root execution runner.

The runner creates:

- user namespace
- mount namespace
- PID namespace
- UTS namespace
- IPC namespace
- network namespace
- memory-backed private root
- isolated process filesystem
- restricted device filesystem
- restricted temporary directory
- restricted workspace

The target remains PID 1 after execution replacement.

The private root exposes:

- read-only `/usr`
- a minimal `/etc`
- read-only project directory
- writable `tmpfs` workspace
- selected device nodes
- isolated `/proc`

The minimal `/etc` contains only required runtime files and certificate material. It does not expose the host password database or `/etc/shadow`.

Security controls applied before the target executes:

- all capabilities removed
- bounding capability set cleared
- ambient capabilities cleared
- `NoNewPrivileges` enabled
- isolated hostname
- isolated network by default
- project filesystem read-only
- workspace marked `nosuid`, `nodev` and `noexec`

The runner remains independent from the stable sandbox execution path until further integration and evaluation are completed.
