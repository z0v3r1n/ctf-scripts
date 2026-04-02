#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

char* guys[8];
size_t cnt = 16;
size_t cnt2 = 4;
bool used_0 = 0;
bool used_40 = 0;
bool used_224 = 0;

size_t read_int() {
    char buf[16] = {0};
    read(0, buf, 15);
    return atol(buf);
}

size_t read_line(char *buf, size_t n) {
  ssize_t r = 0;
  size_t i = 0;
  char c = 0;
  while (i < n) {
    r = read(0, &c, 1);
    if (r <= 0 || c == '\n') break;
    buf[i++] = c;
  }
  return i;
}

void add() {
    if (!cnt--) _exit(1);
    printf("idx: ");
    size_t idx = read_int();
    if (idx > 7) _exit(1);
    if (guys[idx] != NULL) _exit(1);
    printf("size: ");
    size_t size = read_int();
    if (!(1032 < size && size < 1241)) _exit(1);
    guys[idx] = calloc(size, 1);
    printf("data: ");
    size_t nread = read_line(guys[idx], size+2);
    if (nread > size && !cnt2--) _exit(1);
}

void del() {
    printf("idx: ");
    size_t idx = read_int();
    if (idx > 7) _exit(1);
    if (guys[idx] == NULL) _exit(1);
    free(guys[idx]);
    guys[idx] = NULL;
}

void gift() {
    printf("size: ");
    size_t size = read_int();
    if (!used_0 && size == 0) {
        read_line(calloc(size,1), size);
        used_0 = 1;
    } else if (used_0 && !used_40 && size == 40) {
        read_line(malloc(size), size);
        used_40 = 1;
    } else if (used_0 && used_40 && !used_224 && size == 224) {
        read_line(calloc(size,1), size);
        used_224 = 1;
    } else {
        _exit(1);
    }
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    while (1) {
        printf("1. add\n");
        printf("2. del\n");
        printf("3. gift\n");
        printf(">> ");
        size_t choice = read_int();
        switch (choice) {
            case 1:
                add();
                break;
            case 2:
                del();
                break;
            case 3:
                gift();
                break;
            default:
                _exit(0);
        }
    }
}