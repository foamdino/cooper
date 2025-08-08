/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// TODO rename/refactor this when it's working
//- I think we separate the queue semantics from the thread semantics
//- threads go int cooper_thread_workers/manager
//- queue I think should be extracted from log and this and made generic queue
#ifndef CLASS_QUEUE_H
#define CLASS_QUEUE_H

#include <jvmti.h>
#include <pthread.h>

#define CLASS_Q_SZ 256 /* Adjust based on expected load */

typedef struct class_q_entry class_q_entry_t;
typedef struct class_q class_q_t;

struct class_q_entry
{
	jclass klass;    /* Class reference to process */
	char *class_sig; /* Class signature (for logging) */
};

struct class_q
{
	class_q_entry_t entries[CLASS_Q_SZ];
	int hd;
	int tl;
	int count;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int running;
};

/* Initialize the class processing queue */
int class_queue_init(class_q_t *q);

/* Enqueue a class for deferred processing */
int class_queue_enqueue(class_q_t *q, jclass klass, const char *class_sig);

/* Dequeue a class for processing */
class_q_entry_t *class_queue_dequeue(class_q_t *q);

/* Cleanup the queue */
void class_queue_cleanup(class_q_t *q);

/* Check if queue is empty */
int class_queue_is_empty(class_q_t *queue);

#endif /* CLASS_QUEUE_H */