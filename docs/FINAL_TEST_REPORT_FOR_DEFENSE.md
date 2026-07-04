FINAL TEST REPORT FOR DEFENSE

Project Title

منصة ذكية لعزل وتحليل سلوك العمليات في أنظمة Linux باستخدام تقنيات تعلم الآلة للكشف الاستباقي عن التهديدات

Test Objective

يهدف هذا الاختبار إلى إثبات أن المشروع يحقق متطلبات الاستمارة الثانية من خلال تشغيل النظام، اختبار الطبقات الثلاث، التحقق من نتائج التحليل، والتأكد من نجاح سيناريوهات العرض العملي.

Test Environment

Operating System: Ubuntu Linux
Programming Language: Python
Tracing Tool: strace
Monitoring Library: psutil
Machine Learning Library: scikit-learn
Logging Format: JSONL
Version Control: Git

Validation Commands

cd ~/ai-sandbox-project
source venv/bin/activate
git status --short
python -m unittest discover -s tests -p "test_*.py"

Expected Test Result

Ran 71 tests
OK

Tested Components

Sandbox Runner: Passed
Command Policy Layer: Passed
Resource Limits: Passed
Process Monitoring Engine: Passed
strace Parser: Passed
Syscall Summary Engine: Passed
Behavioral Feature Extractor: Passed
Detection Rules Engine: Passed
Risk Scoring Engine: Passed
Machine Learning Analysis Layer: Passed
Final Decision Engine: Passed
Monitoring Interface: Passed
JSONL Logging: Passed

Final Demo Scenarios

Scenario 1: Safe Process

Expected Result:
risk_level = low
final_decision = allow
passed = true

Scenario 2: Sensitive Path Access

Expected Result:
risk_level = suspicious
triggered_rule = SENSITIVE_PATH_ACCESS
final_decision = review
passed = true

Scenario 3: Dangerous Command

Expected Result:
risk_level = high
triggered_rule = POLICY_BLOCKED_COMMAND
final_decision = block_or_investigate
passed = true

Evidence Files

docs/evidence/final_project_evidence_20260530_214403.txt
docs/evidence/final_project_evidence_20260530_214441.txt
docs/evidence/final_project_evidence_20260530_215942.txt
docs/evidence/final_project_evidence_20260530_220528.txt

Final Assessment

The project passed the final validation successfully. The implementation satisfies the approved second form requirements as an academic fourth-year Informatics Engineering project.
