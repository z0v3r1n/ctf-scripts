all: clean chal
test: clean chal snalloc_test
	./snalloc_test

chal:
ifeq ($(SNDEBUG),)
	gcc -Wall -Wpedantic -Wl,-z,relro,-z,now -g3 -o chal snalloc.c chal.c
else
	gcc -Wall -Wpedantic -Wl,-z,relro,-z,now -g3 -DSNDEBUG -o chal snalloc.c chal.c
endif

snalloc_test:
ifeq ($(SNDEBUG),)
	gcc -Wall -Wpedantic -Wl,-z,relro,-z,now -static-pie -g3 -o snalloc_test snalloc.c snalloc_test.c
else
	gcc -Wall -Wpedantic -Wl,-z,relro,-z,now -static-pie -g3 -DSNDEBUG -o snalloc_test snalloc.c snalloc_test.c
endif

clean:
	rm -f chal snalloc_test
