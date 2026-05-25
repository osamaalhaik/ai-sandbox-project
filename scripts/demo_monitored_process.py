import os
import time

print(f"monitored_pid={os.getpid()}")

data = []

for index in range(10):
    data.append(bytearray(1024 * 1024))
    time.sleep(0.2)

print("monitored_process_done")
