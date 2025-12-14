#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef union {
  struct {
    int32_t capacity;
    int32_t size;
    int32_t initial;
  };
  struct {
    int32_t op;
    int32_t index;
    int32_t value;
  };
} pkt_t;

struct {
  uint32_t size;
  uint32_t capacity;
  int32_t initial;
  int32_t *data;
} g_array;

void fatal(const char *msg) {
  fprintf(stderr, "[ERROR] %s\n", msg);
  exit(1);
}

void read_packet(pkt_t *pkt) {
  if (read(0, pkt, sizeof(pkt_t)) != sizeof(pkt_t))
    fatal("Truncated input");
}

void array_init(pkt_t *pkt) {
  if (pkt->size > pkt->capacity)
    pkt->size = pkt->capacity;

  g_array.data = (int*)malloc(pkt->capacity * sizeof(int));
  if (!g_array.data)
    *(uint64_t*)pkt = 0;

  g_array.size = pkt->size;
  g_array.capacity = pkt->capacity;
  g_array.initial = pkt->initial;

  for (size_t i = 0; i < pkt->size; i++)
    g_array.data[i] = pkt->initial;

  printf("Initialized: size=%d capacity=%d\n", pkt->size, pkt->capacity);
}

void main() {
  pkt_t pkt;
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  read_packet(&pkt);
  array_init(&pkt);

  while (1) {
    read_packet(&pkt);
    switch (pkt.op) {
      case 1: // get
        if (g_array.size <= pkt.index)
          fatal("Out-of-bounds");
        printf("array[%d] = %d\n", pkt.index, g_array.data[pkt.index]);
        break;

      case 2: // set
        if (g_array.size <= pkt.index)
          fatal("Out-of-bounds");
        g_array.data[pkt.index] = pkt.value;
        printf("array[%d] = %d\n", pkt.index, pkt.value);
        break;

      case 3: // resize
        if (g_array.capacity < pkt.size)
          fatal("Over capacity");
        for (int i = g_array.size; i < pkt.size; i++)
          g_array.data[i] = g_array.initial;
        g_array.size = pkt.size;
        printf("New size set to %d\n", pkt.size);
        break;

      default:
        exit(0);
    }
  }
}
