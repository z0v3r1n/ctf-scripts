#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verify_fmt(const char *fmt, size_t n_args) {
  size_t argcnt = 0;
  size_t len = strlen(fmt);

  for (size_t i = 0; i < len; i++) {
    if (fmt[i] == '%') {
      if (fmt[i+1] == '%') {
        i++;
        continue;
      }

      if (isdigit(fmt[i+1])) {
        puts("[-] Positional argument not supported");
        return 1;
      }

      if (argcnt >= n_args) {
        printf("[-] Cannot use more than %lu specifiers\n", n_args);
        return 1;
      }

      argcnt++;
    }
  }

  return 0;
}

int main() {
  size_t n_args;
  long args[4];
  char fmt[256];

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  while (1) {
    /* Get arguments */
    printf("# of args: ");
    if (scanf("%lu", &n_args) != 1) {
      return 1;
    }

    if (n_args > 4) {
      puts("[-] Maximum of 4 arguments supported");
      continue;
    }

    memset(args, 0, sizeof(args));
    for (size_t i = 0; i < n_args; i++) {
      printf("args[%lu]: ", i);
      if (scanf("%ld", args + i) != 1) {
        return 1;
      }
    }

    /* Get format string */
    while (getchar() != '\n');
    printf("Format string: ");
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
      return 1;
    }

    /* Verify format string */
    if (verify_fmt(fmt, n_args)) {
      continue;
    }

    /* Enjoy! */
    printf(fmt, args[0], args[1], args[2], args[3]);
  }

  return 0;
}
