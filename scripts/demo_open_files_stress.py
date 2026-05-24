import sys

handles = []

try:
    while True:
        handles.append(open("/dev/null", "rb"))
except OSError as exc:
    print(f"open_files_limit_reached: {exc}")
    sys.exit(3)
