from pathlib import Path

path = Path("/etc/passwd")
content = path.read_text(encoding="utf-8", errors="ignore").splitlines()

print("sensitive_path_demo_started")
print(f"path={path}")
print(f"lines_read={len(content)}")
