import os
import time

print(f"monitored_pid={os.getpid()}")

data = []

for index in range(5):
    data.append(bytearray(512 * 1024))
    time.sleep(0.1)

print("monitored_process_done")
