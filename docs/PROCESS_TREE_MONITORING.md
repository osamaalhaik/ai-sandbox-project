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

Integration with the traced execution pipeline is performed in the next stage.
