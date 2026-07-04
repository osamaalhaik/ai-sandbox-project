# ProcSentinel AI - Reporting Layer

## Overview

The Reporting Layer converts ProcSentinel AI security data into reviewable, exportable, and defense-ready reports.

It summarizes runtime analysis, gateway decisions, approval decisions, security alerts, highest-risk items, and recommended follow-up actions.

## Current Report Outputs

| Format | Path | Purpose |
|---|---|---|
| JSON | docs/evidence/security_summary_report.json | Machine-readable security summary |
| CSV | docs/evidence/security_summary_report.csv | Spreadsheet-friendly evidence export |
| PDF | docs/evidence/security_summary_report.pdf | Supervisor/committee-ready printable report |

## Dashboard Endpoints

| Endpoint | Purpose |
|---|---|
| /reports/security-summary | Dashboard security report page |
| /api/reports/security-summary | JSON report API |
| /api/reports/security-summary.csv | CSV report export |
| /api/reports/security-summary.pdf | PDF report export |

## CLI Export Commands

Generate all report formats:

python scripts/export_security_report.py --output docs/evidence/security_summary_report.json
python scripts/export_security_report_csv.py --output docs/evidence/security_summary_report.csv
python scripts/export_security_report_pdf.py --output docs/evidence/security_summary_report.pdf

## Report Contents

The report includes:

- Executive summary
- Runtime analysis summary
- Gateway decision summary
- Approval summary
- Security alert summary
- Highest-risk items
- Recommended next actions

## Academic Value

The Reporting Layer strengthens the project because it converts raw runtime security events into formal evidence that can be reviewed by supervisors, exported for documentation, and used during the project defense.

## Validation Status

Current expected validation result:

Ran 72 tests
OK

## Current Status

Implemented and validated:

- Dashboard Security Report page
- JSON security report export
- CSV security report export
- PDF security report export
- Automated tests for report generation and API export

Future improvements:

- Improve PDF visual design
- Add charts to reports
- Add Arabic/English report templates
- Add report checksum or digital signature
- Add filtering by date, risk level, and decision type
