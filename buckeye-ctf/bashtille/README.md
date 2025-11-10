```
gcc exploit.c -o exploit
strip exploit
xxd -p exploit | sed 's/../\\x&/g' > exploit.hex
python3 -c "print(open('exploit.hex', 'r').read().replace('\n', ''))" > exploit.hex2
mv exploit.hex2 exploit.hex

python3 xpl.py
```
