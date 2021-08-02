import subprocess
import sys

ok = subprocess.call("cmake -B build && cd build && make", shell = True) == 0
if not ok:
    sys.exit(1)

sys.exit(0)

