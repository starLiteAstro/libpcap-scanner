#ifndef CS241_QUEUE_H
#define CS241_QUEUE_H

#include "sniff.h"

// Data structure for each node
typedef struct node {
    packet pkt;
    struct node *next;
} node;

// Data structure for queue
typedef struct queue {
    node *head;
    node *tail;
} queue;

queue *create_queue(queue *q);
int is_empty(queue *q);
void enqueue(queue *q, packet pkt);
void dequeue(queue *q, packet *pkt);
void destroy_queue(queue *q);

#endif