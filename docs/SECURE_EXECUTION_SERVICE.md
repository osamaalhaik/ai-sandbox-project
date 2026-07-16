# Secure Execution Service

The secure execution service converts an approved gateway execution strategy into a concrete isolation and resource-control profile.

Supported profiles:

- `low`
- `standard`
- `intensive`

Supported strategy mappings:

- `lightweight_sandbox` to `low`
- `workspace_sandbox_with_monitoring` to `standard`
- `restricted_sandbox` to `standard`
- `strong_sandbox` to `intensive`
- `restricted_sandbox_with_confirmation` to `intensive`

The `do_not_execute` strategy fails closed.

Strategies requiring human confirmation cannot execute unless approval has been verified.

Every execution is performed through `PrivateRootRunner` with delegated `cgroups v2` limits.

The persisted evidence includes:

- secure execution identifier
- gateway decision identifier
- private-root run identifier
- execution strategy
- execution profile
- configured limits
- private-root status
- cgroup attachment and cleanup
- CPU throttling
- memory OOM events
- task-limit events
- process-tree monitoring evidence
- complete private-root result
