/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef Q_H
#define Q_H

#include <pthread.h>

#include "log.h"

#define Q_SZ 1024

typedef enum q_entry_type q_entry_type_e;
typedef struct q_entry q_entry_t;
typedef struct q q_t;

enum q_entry_type
{
	Q_ENTRY_CLASS,
	Q_ENTRY_LOG,
	Q_ENTRY__LAST
};

struct q_entry
{
	q_entry_type_e type; /**< Type of data represented */
	void *data;          /**< Data */
};

struct q
{
	q_entry_t entries[Q_SZ];
	int hd;
	int tl;
	int count;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	// TODO Do we need this flag?
	int running;
};

/* Initialise the queue */
int q_init(q_t *queue);

/* Enqueue a q_entry for deferred processing */
int q_enq(q_t *q, q_entry_t *entry);

/* Dequeue a class for processing */
q_entry_t *q_deq(q_t *q);

/* Cleanup the queue */
void q_cleanup(q_t *q);

/* Check if queue is empty */
int q_is_empty(q_t *queue);

#endif /* Q_H */