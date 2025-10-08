/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "q.h"

/**
 * Init the q, expects the q to be zero initialised already, caller responsible for that
 *
 * @param queue Pointer to queue
 *
 * @return 0 on success, 1 on failure
 */
int
q_init(q_t *queue)
{
	assert(queue != NULL);

	int err = pthread_mutex_init(&queue->lock, NULL);
	if (err != 0)
		return 1;

	err = pthread_cond_init(&queue->cond, NULL);
	if (err != 0)
	{
		pthread_mutex_destroy(&queue->lock);
		return 1;
	}

	return 0;
}

/**
 * Enqueue an entry for later processing
 *
 * @param queue Pointer to queue to enqueue the entry to
 * @param entry Pointer to entry to enqueue
 *
 * @return 0 on success, 1 if Q is full
 */
int
q_enq(q_t *queue, q_entry_t *entry)
{
	assert(queue != NULL);
	assert(entry != NULL);

	pthread_mutex_lock(&queue->lock);

	/* Check if queue is full */
	if (queue->count >= Q_SZ)
	{
		pthread_mutex_unlock(&queue->lock);
		return 1;
	}

	/* Add to queue */
	queue->entries[queue->hd] = entry;
	queue->hd                 = (queue->hd + 1) % Q_SZ;
	queue->count++;

	/* Signal waiting thread */
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->lock);

	return 0;
}

/**
 * Dequeue an entry from a queue
 *
 * @param queue Pointer to queue
 *
 * @return a Pointer to a q_entry_t of the entry dequeued
 */
q_entry_t *
q_deq(q_t *queue)
{
	assert(queue != NULL);

	pthread_mutex_lock(&queue->lock);

	/* Wait for entries */
	while (queue->running && queue->count == 0)
		pthread_cond_wait(&queue->cond, &queue->lock);

	/* Check if we should exit */
	if (!queue->running)
	{
		pthread_mutex_unlock(&queue->lock);
		return NULL;
	}

	/* Get entry if available */
	if (queue->count == 0)
	{
		pthread_mutex_unlock(&queue->lock);
		return NULL;
	}

	/* Get entry */
	q_entry_t *entry          = queue->entries[queue->tl];
	queue->entries[queue->tl] = NULL;
	queue->tl                 = (queue->tl + 1) % Q_SZ;
	queue->count--;

	pthread_mutex_unlock(&queue->lock);
	return entry;
}

int
q_is_empty(q_t *queue)
{
	assert(queue != NULL);

	pthread_mutex_lock(&queue->lock);
	int empty = (queue->count == 0);
	pthread_mutex_unlock(&queue->lock);

	return empty;
}

void
q_cleanup(q_t *queue)
{
	assert(queue != NULL);

	/* Signal shutdown */
	pthread_mutex_lock(&queue->lock);
	queue->running = 0;
	pthread_cond_broadcast(&queue->cond);
	pthread_mutex_unlock(&queue->lock);

	/* Cleanup synchronization primitives */
	pthread_cond_destroy(&queue->cond);
	pthread_mutex_destroy(&queue->lock);
}