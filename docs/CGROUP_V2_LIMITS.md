# cgroups v2 Resource Controls

ProcSentinel AI includes an independent manager for delegated `cgroups v2`.

The manager controls:

- CPU quota and period through `cpu.max`
- memory ceiling through `memory.max`
- optional memory pressure threshold through `memory.high`
- swap ceiling through `memory.swap.max`
- process and thread count through `pids.max`

Each execution receives an independent child control group.

Recorded evidence includes:

- `cpu.stat`
- `memory.current`
- `memory.peak`
- `memory.events`
- `memory.events.local`
- `pids.current`
- `pids.events`
- configured controller values
- CPU throttling detection
- OOM kill detection
- task-limit event detection

The service requires delegated `cpu`, `memory` and `pids` controllers.

The service configuration must include:

- `Delegate=cpu memory pids`
- `ProtectControlGroups=no`
- CPU accounting
- memory accounting
- task accounting

Resource control integration with `PrivateRootRunner` is performed only after the independent manager and kernel enforcement tests pass.
