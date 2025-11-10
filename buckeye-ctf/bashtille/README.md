```
gcc exploit.c -o exploit
strip exploit

python3 - <<'PY' > exploit.hex
import sys
sys.stdout.write("".join("\\x%02x"%b for b in open("exploit","rb").read()))
PY

python3 xpl.py
```
