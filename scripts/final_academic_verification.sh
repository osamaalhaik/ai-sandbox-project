#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "===== GIT STATE ====="
git status -sb
git log --oneline --decorate -n 8

echo
echo "===== COMPILE CHECK ====="
python -m compileall app scripts tests

echo
echo "===== UNIT TESTS ====="
python -m unittest discover -s tests -p "test_*.py"

echo
echo "===== EXPORT SECURITY REPORTS ====="
python scripts/export_security_report.py --output docs/evidence/security_summary_report.json
python scripts/export_security_report_csv.py --output docs/evidence/security_summary_report.csv
python scripts/export_security_report_pdf.py --output docs/evidence/security_summary_report.pdf

echo
echo "===== REPORT FILES ====="
ls -lah docs/evidence/security_summary_report.*

echo
echo "===== OLD TEST COUNTS CHECK ====="
if grep -RInE "Ran 58|58 tests|Ran 62|62 tests|Ran 68|68 tests|Ran 71|71 tests" README.md docs --exclude-dir=evidence 2>/dev/null; then
    echo "OLD_TEST_COUNT_FOUND"
    exit 1
fi

echo "NO_OLD_TEST_COUNTS_FOUND"

echo
echo "===== FINAL STATUS ====="
git status -sb

echo
echo "FINAL_ACADEMIC_VERIFICATION_DONE"
