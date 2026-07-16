# Secure Execution Persistence

Secure execution records are persisted in the `secure_executions` database table.

The table stores:

- secure execution identifier
- gateway decision identifier
- private-root run identifier
- command and working directory
- execution strategy and resource profile
- approval state
- execution status and failure reason
- private-root evidence
- cgroup attachment and cleanup evidence
- CPU throttling evidence
- OOM-kill evidence
- task-limit evidence
- process-monitoring counts
- configured profile
- complete execution result
- execution timestamps

The JSONL evidence file remains the append-only execution source.

Database synchronization performs idempotent upserts based on `secure_execution_id`.

API routes:

- `POST /api/secure-executions/import`
- `GET /api/secure-executions`
- `GET /api/secure-executions/summary`
- `GET /api/secure-executions/{secure_execution_id}`
