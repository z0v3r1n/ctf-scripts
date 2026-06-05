#include "snalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERR_CODE 1

#define MAX_ALLOCS 0x1000
#define MAX_ALLOC_SIZE ORDER_2_CHUNK_SZ(SNAB_MAX_ORDER)

enum { ALLOC = 0, EDIT = 1, FREE = 2, CMDS = 3 };
enum { MALLOC = 1, SNALLOC = 2 };

typedef struct {
  char *buf;
  size_t size;
} alloc_t;

static alloc_t mallocs[MAX_ALLOCS];
static alloc_t snallocs[MAX_ALLOCS];

const char banner[] =
    " ________  _________  ___  ___       ___                             \n"
    "|\\   ____\\|\\___   ___\\\\  \\|\\  \\     |\\  \\                       "
    "     \n"
    "\\ \\  \\___|\\|___ \\  \\_\\ \\  \\ \\  \\    \\ \\  \\                  "
    "         \n"
    " \\ \\_____  \\   \\ \\  \\ \\ \\  \\ \\  \\    \\ \\  \\                 "
    "         \n"
    "  \\|____|\\  \\   \\ \\  \\ \\ \\  \\ \\  \\____\\ \\  \\____            "
    "         \n"
    "    ____\\_\\  \\   \\ \\__\\ \\ \\__\\ \\_______\\ \\_______\\           "
    "        \n"
    "   |\\_________\\   \\|__|  \\|__|\\|_______|\\|_______|                  "
    " \n"
    "   \\|_________|                                                      \n"
    "                                                                     \n"
    "                                                                     \n"
    " ________   ________  _________                                      \n"
    "|\\   ___  \\|\\   __  \\|\\___   ___\\                                   "
    " \n"
    "\\ \\  \\\\ \\  \\ \\  \\|\\  \\|___ \\  \\_|                             "
    "       \n"
    " \\ \\  \\\\ \\  \\ \\  \\\\\\  \\   \\ \\  \\                            "
    "         \n"
    "  \\ \\  \\\\ \\  \\ \\  \\\\\\  \\   \\ \\  \\                           "
    "         \n"
    "   \\ \\__\\\\ \\__\\ \\_______\\   \\ \\__\\                             "
    "      \n"
    "    \\|__| \\|__|\\|_______|    \\|__|                                   "
    "\n"
    "                                                                     \n"
    "                                                                     \n"
    "                                                                     \n"
    " _____ ______   ________  ___       ___       ________  ________     \n"
    "|\\   _ \\  _   \\|\\   __  \\|\\  \\     |\\  \\     |\\   __  \\|\\   "
    "____\\    \n"
    "\\ \\  \\\\\\__\\ \\  \\ \\  \\|\\  \\ \\  \\    \\ \\  \\    \\ \\  "
    "\\|\\  \\ \\  \\___|    \n"
    " \\ \\  \\\\|__| \\  \\ \\   __  \\ \\  \\    \\ \\  \\    \\ \\  \\\\\\  "
    "\\ \\  \\       \n"
    "  \\ \\  \\    \\ \\  \\ \\  \\ \\  \\ \\  \\____\\ \\  \\____\\ \\  "
    "\\\\\\  \\ \\  \\____  \n"
    "   \\ \\__\\    \\ \\__\\ \\__\\ \\__\\ \\_______\\ \\_______\\ "
    "\\_______\\ \\_______\\\n"
    "    \\|__|     "
    "\\|__|\\|__|\\|__|\\|_______|\\|_______|\\|_______|\\|_______|\n"
    "\n\nEnjoy :P";

#define MAX_BUF 0x100

size_t readline(char *buf, size_t size) {
  ssize_t r = 0;
  size_t n = 0;
  char c = 0;
  while (n < size) {
    r = read(STDIN_FILENO, &c, sizeof c);
    if (r <= 0 || c == '\n') break;
    buf[n++] = c;
  }
  return n;
}

size_t getnum(char *prompt) {
  size_t n = 0;
  printf("%s> ", prompt);
  scanf("%zu", &n);
  while (getchar() != '\n');
  return n;
}

int ask_use_snalloc() {
  size_t allocator = 0;
  puts("\n1 - malloc\n2 - snalloc");
  allocator = getnum("allocator");
  return allocator == SNALLOC;
}

alloc_t *get_alloc(int is_snalloc, size_t idx) {
  if (idx >= MAX_ALLOCS) return NULL;
  if (is_snalloc) return &snallocs[idx];
  if (!is_snalloc) return &mallocs[idx];
  return NULL;
}

void do_cmd(size_t cmd) {
  int is_snalloc = 0;
  size_t idx = 0;
  alloc_t *alloc = NULL;
  size_t size = 0;

  is_snalloc = ask_use_snalloc();
  idx = getnum("idx");
  alloc = get_alloc(is_snalloc, idx);

  if (!alloc->buf && cmd != ALLOC) { puts("empty chunk"); return; }

  switch (cmd) {
    case ALLOC:
      size = getnum("size");
      if (size > MAX_ALLOC_SIZE) { puts("size too big"); return; }
      if (is_snalloc) { alloc->buf = snalloc(size); }
      else alloc->buf = malloc(size);
      if (!alloc->buf) { perror("alloc"); return; }
      alloc->size = size;
      return;

    case EDIT:
      printf("content> ");
      readline(alloc->buf, alloc->size);
      return;

    case FREE:
      if (is_snalloc) snfree(alloc->buf);
      else free(alloc->buf);
      alloc->buf = NULL;
      alloc->size = 0;
      return;
    default: return;
  }
}

int main(int argc, char *argv[]) {
  size_t cmd = 0;

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  puts(banner);

  while (1) {
    puts("\n1 - alloc\n2 - edit\n3 - free");
    cmd = getnum("cmd") - 1;
    if (cmd >= CMDS) _exit(ERR_CODE);
    do_cmd(cmd);
  }
}
