#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct sockaddr_in cli, addr = {0};
  socklen_t clen;
  int cfd, sfd = -1, yes = 1;
  ssize_t n;
  char buf[0x100];
  unsigned short port = argc < 2 ? 31337 : atoi(argv[1]);

  if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    goto err;
  }

  if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
    perror("setsockopt(SO_REUSEADDR)");
    goto err;
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind");
    goto err;
  }

  if (listen(sfd, 1) < 0) {
    perror("listen");
    goto err;
  }

  clen = sizeof(cli);
  if ((cfd = accept(sfd, (struct sockaddr*)&cli, &clen)) < 0) {
    perror("accept");
    goto err;
  }

  while (1) {
    n = 0;
    recv(cfd, &n, sizeof(ssize_t), MSG_WAITALL);
    if (n <= 0 || n >= 0x200)
      break;

    recv(cfd, buf, n, MSG_WAITALL);
    send(cfd, buf, n, 0);
  }

  return 0;

err:
  if (sfd >= 0) close(sfd);
  return 1;
}
