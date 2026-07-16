# Process Tree Monitoring

ProcSentinel AI monitors the complete process tree instead of collecting resources only from the root process.

The process tree sample aggregates:

- CPU usage
- RSS memory
- VMS memory
- thread count
- open file count
- network connection count
- process count
- descendant count

The original fields remain available for compatibility.

Additional evidence fields are:

- `root_pid`
- `target_pid`
- `wrapper_pid`
- `process_count`
- `monitored_pids`
- `connections_count`

Each process is deduplicated using its PID and creation time.

The monitoring core is integrated with the normal `SandboxRunner`.

Every completed sandbox result now records:

- `monitor_root_pid`
- `target_pid`
- `monitored_pids`
- `max_processes_observed`

The monitoring core is also integrated with traced execution.

During traced execution:

- `wrapper_pid` identifies the `strace` process
- `target_pid` identifies the traced application
- `strace` is excluded from application resource totals
- descendants of the target application are aggregated
- `monitored_pids` contains only application-tree processes
- `max_processes_observed` records the largest observed tree size
## Transient Wrapper Startup

A traced application may not exist during the first monitoring samples because the `strace` wrapper starts before its child target.

Raw samples preserve `no_monitored_processes` as evidence. The summary treats this state as transient when a valid target process appears later in the same run.

If no target process is observed during the entire run, the condition remains a monitoring error.
