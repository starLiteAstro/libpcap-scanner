#include <stdio.h>
#include <stdlib.h>

#include "queue.h"
#include "sniff.h"

// Creates a queue and returns its pointer
queue *create_queue(queue *q) {
    q->head = NULL;
    q->tail = NULL;
    return(q);
}

// Checks if queue is empty
int is_empty(queue *q) {
    return(q->head == NULL);
}

// Enqueues a node with a packet
void enqueue(queue *q, packet pkt) {
    node *new_node = (node *) malloc(sizeof(node));
    new_node->pkt = pkt;
    new_node->next = NULL;
    if (is_empty(q)) {
        q->head = new_node;
        q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }
}

// Dequeues the head node
void dequeue(queue *q, packet *pkt) {
    if (is_empty(q)) {
        printf("Error: attempt to dequeue from an empty queue\n");
    } else {
        node *head_node = q->head;
        *pkt = head_node->pkt;
        q->head = head_node->next;
        if (q->head == NULL) {
            q->tail = NULL;
        }
        free(head_node);
        head_node = NULL; // Set head pointer to NULL to avoid dangling pointer
    }
}

// Destroys the queue and frees the memory
void destroy_queue(queue *q){
    while(!is_empty(q)){
        packet temp_pkt; // Temporary packet to store the dequeued packet
        dequeue(q, &temp_pkt);
    }
}