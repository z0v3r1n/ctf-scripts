#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef uint64_t bitmap_t;
typedef uint64_t magic_t;
typedef uint64_t order_t;

#define SNAB_AUTO 1
#define SNAB_EXTEND 2

#define SNAB_MAX_ORDER 3
#define SNAB_CHUNKS (8 * sizeof(bitmap_t))

#define PAGE 0x1000

#define ORDER_2_SNAB_SZ(order) (((order) + 2) * PAGE)
#define ORDER_2_CHUNK_SZ(order) ((ORDER_2_SNAB_SZ(order) - PAGE) / SNAB_CHUNKS)

#define CHUNK_SZ_2_ORDER(chunk_sz)                                             \
  ((chunk_sz) ? ((chunk_sz) * SNAB_CHUNKS - 1) / PAGE : 0)

#define SNAB_MAGIC(snab) (((uint64_t)(snab)) >> 12)

typedef struct snab_t {
  magic_t magic;
  uint64_t flags;
  order_t order;
  bitmap_t bitmap;
  struct snab_t *prev;
  struct snab_t *next;
} snab_t;

void *snalloc(size_t size);
void snfree(void *chunk);

snab_t *snab_alloc(order_t order, size_t flags, snab_t *prev);
void snab_free(snab_t *snab);

snab_t *get_snab_from_chunk(void *chunk);
snab_t *chunk_snab_get(void *chunk);
size_t snab_chunk_idx_get(snab_t *snab, void *chunk);
