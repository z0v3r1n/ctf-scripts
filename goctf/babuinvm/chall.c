#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

enum {
    OP_RESTART,
    OP_RESTART_DUP,
    OP_SET,
    OP_ADD,
    OP_MUL,
    OP_DIV,
    OP_MOV,
    OP_XCHG,
    OP_ADD_NOTE,
    OP_DEL_NOTE,
    OP_NOP
};

typedef unsigned __int128 num_t;

#pragma pack(push,1)
typedef struct {
    uint8_t opcode;
    num_t operand;
} insn_t;
#pragma pack(pop)

#define N_REGS 15
#define N_NOTES 16
num_t regs[N_REGS] = {0};
num_t *notes[N_NOTES] = {0};
size_t cnt_rounds = 300;
size_t cnt_dup = 1;

uint8_t run(insn_t *ops, size_t n_opcodes) {
    for (int i = 0; i < n_opcodes; i++) {
        switch (ops[i].opcode) {
            case OP_SET: {
                regs[0] = ops[i].operand;
            } break;
            case OP_ADD: {
                num_t reg_idx = ops[i].operand;
                if (reg_idx >= N_REGS) _exit(1);
                regs[0] += regs[reg_idx];
            } break;
            case OP_MUL: {
                num_t reg_idx = ops[i].operand;
                if (reg_idx >= N_REGS) _exit(1);
                regs[0] *= regs[reg_idx];
            } break;
            case OP_DIV: {
                num_t reg_idx = ops[i].operand;
                if (reg_idx >= N_REGS) _exit(1);
                regs[0] /= regs[reg_idx];
            } break;
            case OP_MOV: {
                num_t reg_idx = ops[i].operand;
                if (reg_idx >= N_REGS) _exit(1);
                regs[reg_idx] = regs[0];
            } break;
            case OP_XCHG: {
                num_t reg_idx = ops[i].operand;
                if (reg_idx >= N_REGS) _exit(1);
                num_t tmp = regs[0];
                regs[0] = regs[reg_idx];
                regs[reg_idx] = tmp;
            } break;
            case OP_ADD_NOTE: {
                num_t note_idx = ops[i].operand;
                if (note_idx >= N_NOTES) _exit(1);
                if (notes[note_idx] != NULL) _exit(1);
                notes[note_idx] = (num_t*)calloc(N_REGS, sizeof(num_t));
                memmove(notes[note_idx], regs, N_REGS*sizeof(num_t));
            } break;
            case OP_DEL_NOTE: {
                num_t note_idx = ops[i].operand;
                if (note_idx >= N_NOTES) _exit(1);
                if (notes[note_idx] == NULL) _exit(1);
                free(notes[note_idx]);
                notes[note_idx] = NULL;
            } break;
            case OP_NOP: break;
            case OP_RESTART: return 1;
            case OP_RESTART_DUP: return 2;
            default: _exit(1);
        }
    }
    return 0;
}

size_t read_line(char *buf, size_t n) {
    ssize_t r = 0;
    size_t i = 0;
    while (i <= n) {
        char c = 0;
        r = read(0, &c, 1);
        if (r <= 0) _exit(1);
        if (c == '\n') break;
        buf[i++] = c;
    }
    return i;
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    while (1) {
        if (!cnt_rounds--) _exit(1);
        write(1, "Enter bytecode:\n", 16);
        insn_t *bytecode = calloc(248, 1);
        if (read_line((char*)bytecode, 248) == 0) _exit(1);
        uint8_t status = run(bytecode, 248/sizeof(insn_t));
        if (status == 2 && cnt_dup && cnt_dup--) continue;
        if (status == 0) break;
        free(bytecode);
    }
    _exit(0);
}
