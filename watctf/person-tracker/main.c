#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef FLAGVAR
// In the server-side binary, `FLAGVAR` is set to the flag
const volatile char * const FLAG = FLAGVAR;
#else
const volatile char * const FLAG = "fakectf{not the real flag}";
#endif

typedef struct Person {
    uint64_t age;
    char name[24];
    struct Person *next;
} Person;

Person *root = NULL;

uint64_t person_count = 0;

Person *person_at_index(int idx) {
    Person *res = root;
    while (idx > 0) {
        res = res->next;
        idx--;
    }
    return res;
}

int main() {
    puts("Welcome to the Person Tracker!");
    while(1) {
        puts("MENU CHOICES:");
        puts("1. Add a new person");
        puts("2. View a person's information");
        puts("3. Update a person's information");
        printf("Enter your choice: ");
        fflush(stdout);
        int choice;
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n'); 
            continue;
        }
        getchar();
        if (choice == 1) {
            Person *new = malloc(sizeof(Person));
            new->next = root;
            root = new;
            person_count++;
            printf("Enter their age: ");
            fflush(stdout);
            scanf("%lu", &new->age);
            getchar();
            printf("Enter their name: ");
            fflush(stdout);
            fgets(new->name, sizeof(new->name) + 1, stdin); // +1 for null byte
            puts("New person prepended!");
        } else if (choice == 2) {
            printf("Specify the index of the person: ");
            fflush(stdout);
            int idx;
            scanf("%d", &idx);
            getchar();
            if (idx < 0 || idx >= person_count) {
                puts("Invalid index!");
                continue;
            }
            Person *p = person_at_index(idx);
            puts("What information do you want to view?");
            puts("1. Their age");
            puts("2. Their name");
            printf("Enter choice: ");
            fflush(stdout);
            int choice2;
            scanf("%d", &choice2);
            getchar();
            if (choice2 == 1) {
                printf("Their age is %lu\n", p->age);
            } else if (choice2 == 2) {
                printf("Their name is %s\n", p->name);
            }
        } else if (choice == 3) {
            printf("Specify the index of the person: ");
            fflush(stdout);
            int idx;
            scanf("%d", &idx);
            getchar();
            if (idx < 0 || idx >= person_count) {
                puts("Invalid index!");
                continue;
            }
            Person *p = person_at_index(idx);
            puts("What information do you want to modify?");
            puts("1. Their age");
            puts("2. Their name");
            printf("Enter choice: ");
            fflush(stdout);
            int choice2;
            scanf("%d", &choice2);
            getchar();
            if (choice2 == 1) {
                printf("Enter their age: ");
                fflush(stdout);
                scanf("%lu", &p->age);
                getchar();
            } else if (choice2 == 2) {
                printf("Enter the new name: ");
                fflush(stdout);
                fgets(p->name, sizeof(p->name) + 1, stdin); // +1 for null byte
            }
            puts("Updated successfully!");
        }
    }
}
