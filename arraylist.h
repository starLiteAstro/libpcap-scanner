#ifndef CS241_ARRAYLIST_H
#define CS241_ARRAYLIST_H

#include <arpa/inet.h>

// Data structure for arraylist
typedef struct arraylist {
    u_int32_t *addresses;
    unsigned int capacity;
    unsigned int size;
} arraylist;

int create_arraylist(arraylist *arr);
int add(arraylist *arr, u_int32_t addr);
void destroy(arraylist *arr);
int partition(arraylist *list, int low, int high);
void quicksort(arraylist *list, int low, int high);
unsigned int count_unique(arraylist *list, int low, int high);

#endif