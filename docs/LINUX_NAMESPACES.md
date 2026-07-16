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
