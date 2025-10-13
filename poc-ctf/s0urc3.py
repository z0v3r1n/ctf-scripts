encoded_flag = [
    71,105,102,104,88,120,107,108,49,54,103,55,52,45,104,110,51,98,60,58,
    52,98,103,106,55,97,105,110,50,96,55,59,99,49,60,61,56,54,130
]

decoded = []
for i, byte in enumerate(encoded_flag):
    if i % 4 == 0:
        decoded.append(byte ^ 0x01)
    elif i % 4 == 1:
        decoded.append((byte + 3) & 0xFF)
    elif i % 4 == 2:
        decoded.append((byte - 5) & 0xFF)
    elif i % 4 == 3:
        decoded.append(byte ^ 0x0F)

print(bytes(decoded).decode())
