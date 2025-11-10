#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NUM_NOTES 16UL

#define ASSERT_EQ(x, y) { \
    if (x != y) exit(1); \
}

typedef void (*fun)(long, long, long, long);

struct menu_item {
    const char *name;
    const char *args[4];
    fun f;
};

struct note {
    char *content;
    int size;
    int id;
};

static void create_note(int note_size);
static void read_note(long note_id);
static void modify_note(long note_id, int new_note_site);
static void delete_note(long note_id);

const struct menu_item menu[4] = {
    { "Create a note",  { "Note size" }, (fun)create_note },
    { "Read a note",  { "Note ID" }, (fun)read_note },
    { "Modify a note",  { "Note ID", "New size" }, (fun)modify_note },
    { "Delete a note",  { "Note ID" }, (fun)delete_note },
};

struct note notes[NUM_NOTES];

static inline char **note_content_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].content;
    else return nullptr;
}

static inline int *note_size_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].size;
    else return nullptr;
}

static inline int *note_id_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].id;
    else return nullptr;
}

static inline void zero_note(long note_id) {
    if (note_id < NUM_NOTES) {
        memset(&notes[note_id], 0, sizeof(struct note));
    }
}

static inline int find_unused_note() {
    for (int i=0; i<NUM_NOTES; i++) {
        if (*note_content_mut(i) == NULL) {
            *note_id_mut(i) = i;
            return i;
        }
    }
    fprintf(stderr, "Out of notes :(\n");
    exit(1);
}

void create_note(int note_size) {
    long note_id = find_unused_note();
    if (note_size <= 1 || note_size > 0x1000) return;

    *note_content_mut(note_id) = (char*)malloc(note_size);
    *note_size_mut(note_id) = note_size;

    printf("Enter your note: ");
    fflush(stdout);

    fgets(*note_content_mut(note_id), *note_size_mut(note_id), stdin);
    printf("Note ID is %d.\n", *note_id_mut(note_id));
}

void modify_note(long note_id, int note_size) {
    if (*note_content_mut(note_id) == NULL) {
        printf("Note does not exist :(\n");
        return;
    }

    ASSERT_EQ(*note_id_mut(note_id), note_id);

    if (note_size <= 1 || note_size > 0x1000) return;

    *note_content_mut(note_id) = (char *)realloc(*note_content_mut(note_id), note_size);
    *note_size_mut(note_id) = note_size;

    printf("Enter your note: \n");
    fflush(stdout);

    fgets(*note_content_mut(note_id), *note_size_mut(note_id), stdin);
}

void read_note(long note_id) {
    char **content = note_content_mut(note_id);
    if (*content == NULL) {
        printf("Note does not exist :(\n");
        return;
    }

    printf("Note: %s\n", *content);
}

void delete_note(long note_id) {
    char **content = note_content_mut(note_id);
    if (*content == NULL) {
        printf("Note does not exist :(\n");
        return;
    }

    ASSERT_EQ(*note_id_mut(note_id), note_id);
    free(*content);
    zero_note(note_id);
}

long getnum() {
    long res;
    scanf("%ld", &res);
    getchar(); // newline
    return res;
}

int main() {
    while (1) {
        printf("Menu\n");
        int i=0;
        for (auto &mi : menu) {
            printf("%d. %s\n", i+1, mi.name);
            i++;
        }

        printf("> ");
        fflush(stdout);

        unsigned int res;
        if (scanf("%u", &res) != 1) break;
        getchar(); // newline
        res -= 1;

        if (res < sizeof(menu) / sizeof(menu[0])) {
            long args[4];
            int argc = 0;
            while (menu[res].args[argc]) {
                printf("%s? > ", menu[res].args[argc]);
                fflush(stdout);
                args[argc++] = getnum();
            }
            menu[res].f(args[0], args[1], args[2], args[3]);
        } else break;
    }
}

