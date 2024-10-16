#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>

#define N_ENTRIES 10

struct list_entry_t
{
    int id;
    SLIST_ENTRY(list_entry_t)
    next;
};

SLIST_HEAD(list, list_entry_t)
my_list;

void clean_up(void)
{
    struct list_entry_t* entry = NULL;
    while ((entry = SLIST_FIRST(&my_list)) != NULL)
    {
        SLIST_REMOVE_HEAD(&my_list, next);
        printf("Cleaning up entry with id %d\n", entry->id);
        free(entry);
    }
}

struct list_entry_t* get_new_list_entry(void)
{
    struct list_entry_t* new_entry = malloc(sizeof(struct list_entry_t));
    if (NULL == new_entry)
    {
        printf("Could not allocate memory");
        clean_up();
        exit(-1);
    }
    return new_entry;
}

int main(int argc, char* argv[])
{
    int n_entries = N_ENTRIES;
    if (argc == 2)
    {
        n_entries = atoi(argv[1]);

        for (int i = 0; i < n_entries; i++)
        {
            struct list_entry_t* new_list_entry = get_new_list_entry();
            new_list_entry->id = i;
            SLIST_INSERT_HEAD(&my_list, new_list_entry, next);
        }

        struct list_entry_t* current_entry = NULL;
        SLIST_FOREACH(current_entry, &my_list, next)
        {
            printf("Node id : %d\n", current_entry->id);
        }

        clean_up();
    }
}