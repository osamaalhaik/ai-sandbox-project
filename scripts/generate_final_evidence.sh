#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p docs/evidence

OUT="docs/evidence/final_project_evidence_$(date -u +%Y%m%d_%H%M%S).txt"

{
echo "AI SANDBOX FINAL PROJECT EVIDENCE"
echo "================================================================================"
date -u
pwd
echo
echo "GIT STATUS"
echo "================================================================================"
git status --short
echo
echo "PYTHON VERSION"
echo "================================================================================"
python --version
echo
echo "TEST SUITE"
echo "================================================================================"
python -m unittest discover -s tests -p "test_*.py"
echo
echo "FINAL DEMO"
echo "================================================================================"
if [ -f scripts/run_final_demo.py ]; then
python scripts/run_final_demo.py
else
python scripts/run_demo_scenarios.py --scenario all --reset
fi
echo
echo "GENERATED DATA FILES"
echo "================================================================================"
find data -type f | sort
echo
echo "LATEST PROCESSED RESULTS"
echo "================================================================================"
for file in data/processed/*.jsonl; do
if [ -f "$file" ]; then
echo "--- $file"
tail -n 5 "$file"
fi
done
} > "$OUT" 2>&1

echo "$OUT"
