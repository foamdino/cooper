/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_THREAD_MANAGER_H
#define COOPER_THREAD_MANAGER_H

#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "../lib/log.h"
#include "../lib/thread_util.h"
#include "cooper.h"
#include "cooper_shm.h"

/* Simple thread management functions */
int start_all_threads(agent_context_t *ctx);
void stop_all_threads(agent_context_t *ctx);

/* Set a specific worker status bit */
static inline void
set_worker_status(unsigned int *status, unsigned int flag)
{
	*status |= flag;
}

/* Check if a specific worker status bit is set - returns non-zero if set, zero if not set
 */
static inline int
check_worker_status(unsigned int status, unsigned int flag)
{
	return status & flag;
}

/* Clear a specific worker status bit */
static inline void
clear_worker_status(unsigned int *status, unsigned int flag)
{
	*status &= ~flag;
}

#endif /* COOPER_THREAD_MANAGER_H */