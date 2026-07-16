# NoNewPrivileges Security Control

ProcSentinel AI applies the Linux `PR_SET_NO_NEW_PRIVS` process control before executing an allowed command.

The control is inherited across:

- `execve`
- child processes
- descendant processes
- traced execution through `strace`

Once enabled, the process cannot disable it.

This prevents the process tree from gaining additional privileges through:

- set-user-ID executables
- set-group-ID executables
- file capabilities
- privilege transitions that depend on executable metadata

The control does not replace:

- Linux namespaces
- seccomp
- cgroups
- filesystem isolation
- network isolation

Run records expose:

- `no_new_privileges_enabled`

Blocked commands report this field as `false` because no process was created.

## Traced Process Startup Synchronization

The traced execution monitor uses a short rapid-polling phase while waiting for the target process to appear beneath the `strace` wrapper.

After the target is detected, monitoring returns to the configured normal interval.

This prevents short-lived valid commands from producing false monitoring-error alerts while preserving an error when no target process appears during the execution.
