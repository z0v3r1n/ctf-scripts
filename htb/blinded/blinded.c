#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    free(malloc(0x800));
}

size_t vuln() {
    size_t size;
    int i;
    char c;
    if (scanf("%zu %d %hhd", &size, &i, &c) < 3 || size > 0x3e8 || !(0 <= i < size))
        _exit(EXIT_FAILURE);
    char* ptr = malloc(size);
    ptr[i] = c;
    free(ptr);
    return size;
}

int main(int argc, char* argv[]) {
    setup();
    ssize_t rem = (argc < 2) ? LONG_MAX : atoi(argv[1]);
    printf("You only have %zu bytes to see the light... good luck...\n", rem);
    while (rem > 0) {
        rem -= vuln();
    }
    _exit(EXIT_FAILURE);
}
