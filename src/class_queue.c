/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "class_queue.h"
#include "log.h"
#include <string.h>

// TODO - see comment in class_queue.h - this should be generic not copy-paste of log.c,
// just get it working for now then we'll refactor later
int
class_queue_init(class_q_t *queue)
{
	assert(queue != NULL);

	memset(queue, 0, sizeof(class_q_t));
	queue->running = 1;

	int err = pthread_mutex_init(&queue->lock, NULL);
	if (err != 0)
	{
		LOG_ERROR("Failed to init class queue mutex: %d\n", err);
		return 1;
	}

	err = pthread_cond_init(&queue->cond, NULL);
	if (err != 0)
	{
		LOG_ERROR("Failed to init class queue condition: %d\n", err);
		pthread_mutex_destroy(&queue->lock);
		return 1;
	}

	return 0;
}

int
class_queue_enqueue(class_q_t *queue, jclass klass, const char *class_sig)
{
	assert(queue != NULL);
	assert(klass != NULL);

	pthread_mutex_lock(&queue->lock);

	/* Check if queue is full */
	if (queue->count >= CLASS_Q_SZ)
	{
		pthread_mutex_unlock(&queue->lock);
		LOG_WARN("Class queue full, dropping class: %s\n",
		         class_sig ? class_sig : "<unknown>");
		return -1;
	}

	/* Add to queue */
	queue->entries[queue->hd].klass = klass;
	/* Note: class_sig is temporary, copy if needed for logging */
	queue->entries[queue->hd].class_sig = (char *)class_sig;

	queue->hd = (queue->hd + 1) % CLASS_Q_SZ;
	queue->count++;

	/* Signal waiting thread */
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->lock);

	return 0;
}

class_q_entry_t *
class_queue_dequeue(class_q_t *queue)
{
	assert(queue != NULL);

	pthread_mutex_lock(&queue->lock);

	/* Wait for entries */
	while (queue->running && queue->count == 0)
	{
		pthread_cond_wait(&queue->cond, &queue->lock);
	}

	/* Check if we should exit */
	if (!queue->running && queue->count == 0)
	{
		pthread_mutex_unlock(&queue->lock);
		return NULL;
	}

	/* Get entry */
	class_q_entry_t *entry = &queue->entries[queue->tl];
	queue->tl              = (queue->tl + 1) % CLASS_Q_SZ;
	queue->count--;

	pthread_mutex_unlock(&queue->lock);
	return entry;
}

int
class_queue_is_empty(class_q_t *queue)
{
	assert(queue != NULL);

	pthread_mutex_lock(&queue->lock);
	int empty = (queue->count == 0);
	pthread_mutex_unlock(&queue->lock);

	return empty;
}

void
class_queue_cleanup(class_q_t *queue)
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