import sys

poly = 3988292384
table = []
for byte in range(256):
    xxx = 0
    b = byte
    for _ in range(8):
        if (b ^ xxx) & 1:
            xxx = (xxx >> 1) ^ poly
        else:
            xxx = xxx >> 1
        b = b >> 1
    table.append(xxx)

def zzz42(string):
    value = 0xFFFFFFFF
    for ch in string:
        index = (ord(ch) ^ value) & 0xFF
        value = table[index] ^ (value >> 8)
    return (0xFFFFFFFF - value) & 0xFFFFFFFF

expected = [
    2508312701,
    1231198871, 
    1473663577,
    1022026391,
    4277043751,
    1684325040
]

found = [None] * 6

wordlist_path = sys.argv[1]

with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line_num, line in enumerate(f, 1):
        password = line.strip()
        crc = zzz42(password)
        
        for i, exp in enumerate(expected):
            if crc == exp and found[i] is None:
                found[i] = password
                print(f"FOUND [{i}]: '{password}' -> {crc}")
