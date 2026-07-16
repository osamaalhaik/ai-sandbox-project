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

This phase establishes the monitoring core. Integration with the normal sandbox runner and the traced execution pipeline is performed in separate stages.
