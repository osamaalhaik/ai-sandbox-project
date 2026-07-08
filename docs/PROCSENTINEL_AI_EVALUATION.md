# ProcSentinel AI - AI Evaluation Evidence

## Overview

This document explains how the AI layer is evaluated and positioned inside ProcSentinel AI.

The AI layer is not the only decision maker. It is an assistant signal that supports the final decision together with context-aware security policy, workspace isolation, rule-based detection, risk scoring, human approval workflow, and audit trail.

## Evaluation Scenarios

| Scenario | Context | Rule Risk | AI Prediction | AI Risk | Final Decision |
|---|---|---|---|---|---|
| Safe workspace command | inside_workspace | low | normal | low | allow_with_monitoring |
| Outside workspace command | outside_workspace | high | anomaly | suspicious | require_confirmation |
| Sensitive path access | sensitive_path | suspicious | anomaly | suspicious | review |
| Critical system path delete | critical_path | critical | anomaly | high | block_critical |

## Evidence Files

docs/evidence/ai_evaluation_report.json
docs/evidence/ai_evaluation_report.csv

## Export Command

python scripts/export_ai_evaluation.py

## Academic Defense Statement

The AI layer is used as a supporting anomaly signal. The final security decision is not based on AI alone; it is produced from a combination of context analysis, rules, risk scoring, approval policy, and AI-supported behavioral evidence.

## Validation Status

Expected result after this stage:

Ran 84 tests
OK

## Limitations

The current AI evaluation is scenario-based and academic. It is not a production-grade benchmark.

Future work:

- Expand the dataset
- Add quantitative metrics
- Add confusion matrix
- Compare AI output with rule-based decisions over larger samples
- Add model versioning
