PRACTICAL DEMO SCENARIO

Opening

سنقوم الآن بعرض المشروع عمليًا. الهدف من العرض هو إثبات أن النظام يستطيع تشغيل العمليات ضمن بيئة مراقبة، تحليل سلوكها، تتبع استدعاءات النظام، استخراج الخصائص السلوكية، تطبيق قواعد الكشف، استخدام طبقة تعلم الآلة، ثم إنتاج قرار أمني نهائي.

Step 1: Open Project

cd ~/ai-sandbox-project
source venv/bin/activate

Explanation:

في هذه الخطوة ندخل إلى مجلد المشروع ونفعل بيئة Python التي تحتوي على المكتبات المطلوبة.

Step 2: Check Repository Status

git status --short

Expected Result:

No output

Explanation:

عدم ظهور أي ناتج يعني أن نسخة المشروع نظيفة ومحفوظة في Git.

Step 3: Run Automated Tests

python -m unittest discover -s tests -p "test_*.py"

Expected Result:

Ran 80 tests
OK

Explanation:

هذه الاختبارات تتحقق من جميع مكونات المشروع الأساسية، من تشغيل العملية وحتى القرار النهائي.

Step 4: Run Final Demo

python scripts/run_final_demo.py

Explanation:

هذا الأمر يشغل السيناريوهات النهائية الثلاثة المعتمدة في المشروع.

Scenario 1: Safe Process

Expected Result:

final_decision = allow
cybersecurity_risk_level = low
passed = true

Defense Explanation:

هذا السيناريو يمثل عملية آمنة. النظام شغل العملية، راقبها، تتبع استدعاءات النظام، ولم يجد مؤشرات خطورة، لذلك القرار النهائي هو السماح.

Scenario 2: Sensitive Path Access

Expected Result:

final_decision = review
cybersecurity_risk_level = suspicious
triggered_rule = SENSITIVE_PATH_ACCESS
passed = true

Defense Explanation:

هذا السيناريو يمثل عملية وصلت إلى ملف حساس مثل /etc/passwd. النظام اكتشف الوصول من خلال strace، ورفع درجة الخطورة إلى suspicious، ثم أعطى قرار review.

Scenario 3: Dangerous Command

Expected Result:

final_decision = block_or_investigate
cybersecurity_risk_level = high
triggered_rule = POLICY_BLOCKED_COMMAND
passed = true

Defense Explanation:

هذا السيناريو يمثل أمرًا خطرًا مثل rm -rf. النظام منعه قبل التنفيذ من خلال Command Policy، لذلك لم يتم تشغيل العملية ولم يتم إنشاء PID.

Step 5: Show Logs

find data -type f | sort

Explanation:

هنا نعرض ملفات النتائج التي ينتجها النظام، وتشمل سجلات التشغيل، عينات المراقبة، استدعاءات النظام، الخصائص السلوكية، نتائج الكشف، وقرارات النظام النهائية.

Step 6: Show Compliance Document

cat docs/PROJECT_COMPLIANCE_AUDIT.md

Explanation:

هذا الملف يربط كل متطلب من الاستمارة الثانية بالمكون الذي ينفذه داخل المشروع.

Closing

بهذا العرض نثبت أن المشروع يحقق الطبقات الثلاث المطلوبة: طبقة نظم التشغيل، طبقة الأمن السيبراني، وطبقة تحليل السلوك باستخدام تعلم الآلة. كما نثبت أن النظام ينتج قرارات واضحة: allow و review و block_or_investigate.
