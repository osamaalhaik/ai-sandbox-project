# Linux Namespace Runner

ProcSentinel AI includes an independent namespace execution runner.

The initial profile creates:

- user namespace
- mount namespace
- PID namespace
- UTS namespace
- IPC namespace
- network namespace
- private mount propagation
- isolated `/proc` mount

The target process executes as PID 1 inside the PID namespace.

The network namespace contains only an isolated loopback interface by default.

`NoNewPrivileges` is enabled before the target command executes.

The runner records:

- host namespace identifiers
- child namespace identifiers
- namespace comparison results
- wrapper PID
- child PID
- UID and GID
- isolated hostname
- network interfaces
- Linux security status
- timeout state
- target exit code

The target currently receives capabilities scoped to its new user namespace. Capability reduction and filesystem restrictions are separate hardening stages.

The namespace runner remains independent from the stable `SandboxRunner` until its isolation evidence and failure behavior are fully validated.

## Launcher Argument Safety

Security evidence tokens and isolated hostnames are passed using the `--option=value` form.

This prevents values beginning with `-` from being interpreted as command-line options by the namespace entrypoint.

## Capability Reduction

After configuring the isolated hostname, the namespace entrypoint:

- locks securebits against root capability recovery
- clears the ambient capability set
- removes all capabilities from the bounding set
- clears effective capabilities
- clears permitted capabilities
- clears inheritable capabilities
- enables `NoNewPrivileges`

The target remains UID 0 only inside its user namespace, but all capability sets are zero.

Run evidence exposes:

- `capabilities_dropped`
- `CapInh`
- `CapPrm`
- `CapEff`
- `CapBnd`
- `CapAmb`

## Initial Filesystem Isolation

The namespace runner creates a per-run workspace mounted as `tmpfs`.

The workspace uses:

- `nosuid`
- `nodev`
- `noexec`
- mode `0700`
- configurable memory-backed size

The project directory is bind-mounted inside the mount namespace and remounted read-only.

The target receives:

- `PROCSENTINEL_PROJECT_DIR`
- `PROCSENTINEL_WORKSPACE`
- `PROCSENTINEL_FILESYSTEM_ISOLATED`

Run evidence exposes:

- `filesystem_isolated`
- `project_read_only`
- `workspace_tmpfs`
- `workspace_restricted`
- `workspace_dir`
- `workspace_cleaned`

This stage does not yet provide a private root filesystem. Other host paths remain visible subject to the process credentials, namespace boundaries and capability restrictions.
