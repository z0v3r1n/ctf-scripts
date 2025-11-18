from Crypto.Cipher import AES
import itertools
import string

ct = bytes.fromhex('5aed095b21675ec4ceb770994289f72b')
pt = b'\x00' * 16
printable = string.printable

for combo in itertools.product(printable, repeat=3):
    flag = b'amateursCTF{' + ''.join(combo).encode() + b'}'
    if AES.new(flag, AES.MODE_ECB).encrypt(pt) == ct:
        print(flag.decode())
        break
