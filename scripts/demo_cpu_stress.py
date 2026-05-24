import time

value = 0
started_at = time.time()

while True:
    value += 1
    value *= 2
    value %= 999983
