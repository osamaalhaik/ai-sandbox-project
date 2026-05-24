import sys
import time

blocks = []

try:
    while True:
        blocks.append(bytearray(10 * 1024 * 1024))
        time.sleep(0.05)
except MemoryError:
    print("memory_limit_reached")
    sys.exit(2)
