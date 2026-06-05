#include "snalloc.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_SNABS 0x10
snab_t *snabs[SNAB_MAX_ORDER + 1] = {NULL};
size_t snab_count = 0;

size_t snab_chunk_idx_get(snab_t *snab, void *chunk) {
  size_t diff = (size_t)chunk - (size_t)snab - PAGE;
  size_t idx = diff / ORDER_2_CHUNK_SZ(snab->order);

  if (idx < SNAB_CHUNKS) return idx;
  fprintf(stderr, "%s: snab or chunk corrupted (idx)\n", __func__);
  _exit(1);
}

void check_snab_chunk(snab_t *snab, void *chunk) { snab_chunk_idx_get(snab, chunk); }
void check_snab(snab_t *snab) {
  snab_t *prev = snab->prev;
  snab_t *next = snab->next;

  if (prev && snab != prev->next) {
    fprintf(stderr, "%s: snab corrupted (prev)\n", __func__);
    _exit(1);
  }

  if (next && snab != next->prev) {
    fprintf(stderr, "%s: snab corrupted (prev)\n", __func__);
    _exit(1);
  }
}

snab_t *get_snab_from_chunk(void *chunk) {
  snab_t *snab = (snab_t *)((size_t)chunk & ~(PAGE - 1));
  void *snab_min = (char *)snab + PAGE - ORDER_2_SNAB_SZ(SNAB_MAX_ORDER);

  while ((snab->magic != SNAB_MAGIC(snab)) && ((void *)snab >= snab_min)) snab = (snab_t *)((char *)snab - PAGE);
  if ((void *)snab < snab_min) {
    fprintf(stderr, "%s: snab or chunk corrupted (magic)\n", __func__);
    _exit(1);
  }

  check_snab(snab);
  check_snab_chunk(snab, chunk);
  return snab;
}

void *snab_free_chunk_get(snab_t *snab) {
  void *chunk = NULL;

  for (size_t i = 0; i < SNAB_CHUNKS; ++i) {
    if (!((snab->bitmap >> i) & 1)) {
      chunk = (char *)snab + PAGE + ORDER_2_CHUNK_SZ(snab->order) * i;
      snab->bitmap |= (((bitmap_t)1) << i);
      return chunk;
    }
  }

  if (!snab->next && (snab->flags & SNAB_EXTEND) && snab_count < MAX_SNABS) {
    snab->next = snab_alloc(snab->order, snab->flags | SNAB_AUTO, snab);
    ++snab_count;
  }

  if (snab->next) return snab_free_chunk_get(snab->next);
  return NULL;
}

snab_t *_snab_malloc(order_t order, uint64_t flags) {
  snab_t *snab = NULL;
  if (posix_memalign((void **)&snab, PAGE, ORDER_2_SNAB_SZ(order))) return NULL;
  return (snab_t *)snab;
}

snab_t *snab_alloc(order_t order, size_t flags, snab_t *prev) {
  snab_t *snab = NULL;
  if (order > SNAB_MAX_ORDER) return NULL;
  snab = _snab_malloc(order, flags);
  if (snab) {
    snab->magic = SNAB_MAGIC(snab);
    snab->flags = flags;
    snab->order = order;
    snab->bitmap = 0x0;
    snab->prev = prev;
    snab->next = NULL;
  }
  return snab;
}

snab_t *get_snab_from_order(order_t order) {
  snab_t *snab = snabs[order];
  if (!snab) {
    snab = snab_alloc(order, SNAB_EXTEND, NULL);
    snabs[order] = snab;
  }
  return snab;
}

void *snalloc(size_t size) {
  order_t order = CHUNK_SZ_2_ORDER(size);
  snab_t *snab = NULL;
  void *chunk = NULL;

  while (!chunk && order <= SNAB_MAX_ORDER) {
    snab = get_snab_from_order(order);
    chunk = snab_free_chunk_get(snab);
    ++order;
  }

  if (!chunk) errno = ENOMEM;
  return chunk;
}

void _snfree(snab_t *snab, void *chunk) {
  size_t idx = 0;
  snab_t *prev = snab->prev;
  snab_t *next = snab->next;

  idx = snab_chunk_idx_get(snab, chunk);

  if (!((snab->bitmap >> idx) & 1)) {
    fprintf(stderr, "%s: snab double free (idx)\n", __func__);
    _exit(1);
  }

  snab->bitmap &= ~(1ULL << idx);

  if (snab->bitmap || !(snab->flags & SNAB_AUTO)) return;

  if (next) next->prev = prev;
  if (prev) prev->next = next;

  memset(snab, 0, sizeof *snab);
  free(snab);
  --snab_count;
}

void snfree(void *chunk) {
  snab_t *snab = NULL;
  snab = get_snab_from_chunk(chunk);
  _snfree(snab, chunk);
}
