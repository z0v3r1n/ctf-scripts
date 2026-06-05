#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROG_SIZE 0x1000
#define USER_DISPATCH_SWITCH_SIZE 0x1000
#define MESSAGE_SIZE 0x2000

#define MESSAGE_READY 0x1

#define N_REGS 0x100

typedef struct {
  size_t ready;
  size_t size;
  char buf[MESSAGE_SIZE];
} message_t;

typedef enum { IMM = 0, REG = 1, MEM = 2 } operand_type_t;

typedef enum { ADD = 0, SUB = 1, MUL = 2, MOV = 3, BRK = 4, OUT = 5 } opcode_t;

typedef struct {
  operand_type_t type;
  int32_t value;
} operand_t;

typedef struct {
  opcode_t op;
  operand_t a;
  operand_t b;
} ins_t;

typedef struct {
  int32_t regs[N_REGS];
  size_t data_size;
  char *data;
} state_t;

ins_t prog[PROG_SIZE] = {0};

volatile message_t *message = NULL;

void die(char *msg, size_t size) {
  if (size > sizeof message->buf) {
    message->size = sizeof message->buf;
  } else {
    message->size = size;
  }
  memcpy(message->buf, msg, message->size);
  message->ready = 1;
  while (1)
    ;
}

#define DIE(msg) die(msg "\n", __builtin_strlen(msg "\n"))

int32_t *get_operand_addr(state_t *state, operand_t *operand) {
  size_t idx = (size_t)operand->value;
  if (operand->type != MEM && operand->type != REG && operand->type != IMM) {
    DIE("invalid operand type");
  }

  if (operand->type == REG && idx < N_REGS) {
    return &state->regs[idx];
  }

  if (operand->type == MEM && state->data &&
      (size_t)idx <= state->data_size - sizeof(int32_t)) {
    return (int32_t *)&state->data[idx];
  }

  return NULL;
}

int32_t get_operand_value(state_t *state, operand_t *operand) {
  int32_t *addr = NULL;

  if (operand->type == IMM) {
    return operand->value;
  }

  addr = get_operand_addr(state, operand);

  if (!addr) {
    DIE("operand null deref");
  }

  return *addr;
}

void handle_brk(state_t *state, int16_t amount) {
  size_t data_size = state->data_size + amount;
  char *data = NULL;

  if (!data_size) {
    free(state->data);
    state->data = NULL;
    state->data_size = 0;
    return;
  }

  if (data_size <= state->data_size) {
    state->data_size = data_size;
    return;
  }

  data = malloc(data_size);

  if (!data) {
    DIE("malloc failed");
  }

  memcpy(data, state->data, state->data_size);
  free(state->data);
  state->data = data;
  state->data_size = data_size;
}

void process_ins(state_t *state, ins_t *ins) {
  int32_t *a = NULL;
  char *brk = NULL;
  int16_t brk_amount = 0;

  a = get_operand_addr(state, &ins->a);

  if (!a && !(ins->op == BRK || ins->op == OUT)) {
    DIE("null deref");
  }

  switch (ins->op) {
  case ADD:
    *a += get_operand_value(state, &ins->b);
    break;
  case SUB:
    *a -= get_operand_value(state, &ins->b);
    break;
  case MUL:
    *a *= get_operand_value(state, &ins->b);
    break;
  case MOV:
    *a = get_operand_value(state, &ins->b);
    break;
  case BRK:
    brk_amount = (int16_t)ins->a.value;
    handle_brk(state, brk_amount);
    break;
  case OUT:
    if (state->data) {
      die(state->data, state->data_size);
    }
    DIE("null data");
    break;
  default:
    DIE("invalid opcode");
    break;
  }
}

void disable_syscalls() {
  uint8_t *user_dispatch_switch = NULL;

  user_dispatch_switch =
      mmap(NULL, USER_DISPATCH_SWITCH_SIZE, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (user_dispatch_switch == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  *user_dispatch_switch = SYSCALL_DISPATCH_FILTER_BLOCK;

  if (mprotect(user_dispatch_switch, USER_DISPATCH_SWITCH_SIZE, PROT_READ)) {
    perror("mprotect");
    exit(EXIT_FAILURE);
  }

  if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0, 0,
            user_dispatch_switch)) {
    perror("prctl");
    exit(EXIT_FAILURE);
  }
}

int wait_data(pid_t pid) {
  while (!message->ready)
    ;

  kill(pid, SIGKILL);

  if (waitpid(pid, NULL, 0) < 0) {
    perror("waitpid");
    return EXIT_FAILURE;
  }

  message->ready = 0;
  if (message->size > MESSAGE_SIZE) {
    message->size = MESSAGE_SIZE;
  }

  if (write(STDOUT_FILENO, message->buf, message->size) < 0) {
    perror("write");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

void process_prog() {
  state_t *state = NULL;

  state = calloc(1, sizeof *state);

  if (!state) {
    DIE("calloc failed");
  }

  for (size_t i = 0; i < PROG_SIZE; ++i) {
    process_ins(state, &prog[i]);
  }
}

int main(int argc, char **argv) {
  pid_t pid = -1;

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  message = mmap(NULL, sizeof *message, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (message == MAP_FAILED) {
    perror("mmap");
    return EXIT_FAILURE;
  }

  pid = fork();

  if (pid < 0) {
    perror("fork");
    return EXIT_FAILURE;
  }

  if (pid) {
    return wait_data(pid);
  }

  printf("prog> ");

  read(STDIN_FILENO, prog, sizeof prog);

  disable_syscalls();

  process_prog();

  return EXIT_SUCCESS;
}
