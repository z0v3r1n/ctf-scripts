// given by the author
// god bless him!

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <wchar.h>

static const int MAX_ITEMS = 17;
# define DEBUG 0

typedef struct{
    char name[40];
    char *seller;
    uint32_t price;
    char padding[4];
    char item_id[8];
} item_t;

typedef item_t* Item;
void flush_input();
int call_expert(Item it);

void print_banner(){
    FILE *fp = fopen("banner.txt", "r");
    if(fp == NULL){
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while(fgets(line, sizeof(line), fp) != NULL){
        printf("%s", line);
    }
    fclose(fp);
}

void print_menu(){
    puts("1. sell an item");
    puts("2. buy an item");
    puts("3. change your name");
    puts("4. list items");

    printf("Your choice: ");
}

Item sell_item(){
    Item it = malloc(sizeof(item_t));
    uint32_t price;
    if(it == NULL){
        puts("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    printf("What have you got? ");
    if(fgets(it->name, sizeof(it->name), stdin) == NULL){
        puts("Failed to read item name");
        free(it);
        return NULL;
    
    }

    if( it->name[0] == '\n' || it->name[0] == '\0'){
        puts("Item name cannot be empty");
        free(it);
        exit(EXIT_FAILURE);
    }

    printf("How much do you want for it? ");
    if(scanf("%u", &price) != 1){
        puts("Invalid price");
        free(it);
        return NULL;
    }

    if(price > 1000){
        printf("I have a friend who is an expert in %s. He lives a few blocks away from here, let me call him...\n", it->name);
        if(!call_expert(it)){
            puts("My friend says this item is worthless. I can't pay you for it.");
            free(it);
            return NULL;
        } else {
            puts("My friend says this item is worth something. I'll make you an offer.");
            for(int i=0; i<8; i++){
                it->item_id[i] = 'A' + (rand() % 26);
            }
        }
    }

    price = price / 2;

    printf("Best I can do is %u\n", price);

    printf("Do we have a deal? (y/n) ");
    flush_input();
    char response = getchar();
    flush_input();
    if(response == 'y' || response == 'Y'){
        if(price > 0){
            it->price = price;
        }
        puts("Sold!");
        
        return it;
    } else {
        puts("No deal.");
        return NULL;
    }
}

int buy_item(){
    printf("What would you like to buy? ");
    int code;
    if(scanf("%d", &code) != 1){
        puts("Invalid input");
        exit(EXIT_FAILURE);
    }

    return code;
}

void flush_input(){
    int c;
    while((c = getchar()) != '\n' && c != EOF);
}

int get_choice(){
    int choice;
    if(scanf("%d", &choice) != 1){
        puts("Invalid input");
        exit(EXIT_FAILURE);
    }
    flush_input();
    return choice;
}

int next_free_item(Item *items){
    for(int i=0; i<MAX_ITEMS; i++){
        if(items[i] == NULL)
            return i;
    }
    return -1;
}

void list_items(Item *items){
    puts("Items for sale:");
    for(int i=0; i<MAX_ITEMS; i++){
        if(items[i] != NULL){
            printf("Code %d: ", i);
            puts(items[i]->name);
            if((char)*items[i]->item_id != '\0')
                printf("Item ID: %.8s\n\n", items[i]->item_id);
        }
    }
}

int call_expert(Item it){

    int count = 0;
    char *ptr = it->name;
    
    // delete leading spaces and update ptr
    while(isspace((unsigned char)*ptr)){
        *ptr = '\0';
        ptr++;
    }

    // do not use a copy, the string will be modified
    char *token = strtok(ptr, " ");
    while(token != NULL){
        count++;
        token = strtok(NULL, " ");
    }

    if(count >= 3){
        return 1;
    }
    return 0;
}

int main(int argc, char **argv){
    uint8_t in_use[MAX_ITEMS];
    char seller[16] = "Generic seller";

    for(int i=0; i<MAX_ITEMS; i++)
        in_use[i] = 0;

    #include <sys/mman.h>
    Item *items = mmap(NULL, sizeof(Item) * MAX_ITEMS, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (items == MAP_FAILED) {
        puts("Failed to mmap items array");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < MAX_ITEMS; i++)
        items[i] = NULL;
    
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    print_banner();
    print_menu();

    int choice = get_choice();
    Item it = NULL;
    int idx;

    while(choice != 5){
        switch(choice){
            case 1:
                idx = next_free_item(items);
                if(idx == -1){
                    puts("No more space for items!");
                    break;
                }
                it = sell_item();
                if(it != NULL){
                    it->seller = seller;
                    items[idx] = it;
                    in_use[idx] = 1;
                    printf("Item stored with code %d\n", idx);
                }
                break;
            case 2:
                idx = buy_item();
                if(idx < 0 || idx >= MAX_ITEMS || !in_use[idx]){
                    puts("Invalid item code");
                    break;
                }
                it = items[idx];
                if(it->name[0] == '\0'){
                    puts("This item has no name, I cannot sell it.");
                    free(it);
                    break;
                }
                printf("What's the best you can do for it? ");
                uint32_t offer;
                if(scanf("%u", &offer) != 1){
                    puts("Invalid offer");
                    break;
                }
                if(offer < 2*it->price){
                    puts("If I sold it for that, I’d be losing money the second it leaves the shop");
                } else {
                    puts("Deal!");
                    free(it);
                    items[idx] = NULL;
                    in_use[idx] = 0;
                }
                break;
            case 3:
                printf("Please enter your new username: ");
                if(fgets(seller, sizeof(seller), stdin) == NULL){
                    puts("Failed to read username");
                    exit(EXIT_FAILURE);
                }
                break;
            case 4:
                list_items(items);
                break;
            default:
                puts("Exiting...");
                return 0;
                break;
        }
        print_menu();
        choice = get_choice();
    }

    puts("Goodbye!");
    return 0;
}
