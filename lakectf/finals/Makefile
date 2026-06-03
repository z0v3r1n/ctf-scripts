.PHONY: chal

all: chal

clean:
	rm -f chal

chal:
	gcc -m32 -ggdb -static-pie -Wl,-z,relro,-z,now -fstack-protector-all chal.c -o chal
