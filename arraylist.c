#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arraylist.h"

#define INITIAL_CAPACITY 16

// Create an arraylist
int create_arraylist(arraylist *arr) {
    // Allocate memory
    arr->addresses = malloc(INITIAL_CAPACITY * sizeof(u_int32_t));
    if (arr->addresses == NULL) {
        return -1;
    }
    arr->capacity = INITIAL_CAPACITY;
    arr->size = 0;
    return 0;
}

// Add an address to the arraylist
int add(arraylist *arr, u_int32_t addr) {
    if (arr->size == arr->capacity) {
        // Array full, realloc twice the memory
        u_int32_t *temp = realloc(arr->addresses, 2 * arr->capacity * sizeof(u_int32_t));
        if (temp == NULL) {
            return -1;
        }
        arr->capacity *= 2;
        arr->addresses = temp;
    }
    arr->addresses[arr->size] = addr;
    arr->size++;
    return 0;
}

// Free mempry allocated to arraylist
void destroy(arraylist *arr) {
    free(arr->addresses);
}

// Partition arraylist for quicksort
int partition(arraylist *list, int low, int high) {
    int pivot = list->addresses[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
        if (list->addresses[j] < pivot) {
            i++;
            int temp = list->addresses[i]; // Swap if element is less than pivot
            list->addresses[i] = list->addresses[j];
            list->addresses[j] = temp;
        }
    }
    int temp = list->addresses[i + 1];
    list->addresses[i + 1] = list->addresses[high];
    list->addresses[high] = temp;
    return i + 1;
}

// Quicksort the arraylist (O(n log n) average time)
void quicksort(arraylist *list, int low, int high) {
    if (low < high) {
        int pi = partition(list, low, high);
        quicksort(list, low, pi - 1);
        quicksort(list, pi + 1, high);
    }
}

// Count number of unique elements in the arraylist with recursive divide-and-conquer method (O(log n) average time)
unsigned int count_unique(arraylist *list, int low, int high) {
    int len = high - low;
    if (len == 0) {
        return 0;
    }
    if (list->addresses[low] == list->addresses[high - 1]) {
        return 1; // Same adjacent elements are 1 unique element
    }
    if (len == 2) {
        return 2; // If adjacent elements are not equal, 2 unique elements
    }
    int mid = (low + high) / 2;
    return count_unique(list, low, mid + 1) + count_unique(list, mid, high) - 1; // Recurse by splitting, -1 to account for 2 equal pairs
}