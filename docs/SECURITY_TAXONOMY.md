# ProcSentinel AI Security Taxonomy

## Canonical Risk Levels

| Level | Score | Meaning |
|---|---:|---|
| low | 0–29 | Normal or low-impact behavior |
| suspicious | 30–69 | Behavior requiring monitoring or review |
| high | 70–89 | High-risk behavior requiring intervention |
| critical | 90–100 | Critical behavior requiring immediate blocking |

Legacy values are normalized:

- `minimal` becomes `low`
- `medium` becomes `suspicious`
- `informational` becomes `low`

## Pre-Execution Decisions

| Decision | Meaning |
|---|---|
| `allow` | Execute normally |
| `allow_with_monitoring` | Execute with enhanced monitoring |
| `require_confirmation` | Wait for human approval |
| `block_critical` | Block before execution |

## Runtime Decisions

| Decision | Meaning |
|---|---|
| `allow` | Runtime evidence is safe |
| `review` | Runtime evidence requires investigation |
| `block_or_investigate` | Runtime evidence is high risk |

## Dashboard Buckets

| Bucket | Included Decisions |
|---|---|
| allow | `allow`, `allow_with_monitoring` |
| review | `review`, `require_confirmation` |
| block | `block_critical`, `block_or_investigate` |
