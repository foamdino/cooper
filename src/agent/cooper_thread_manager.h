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

/* Forward declaration */
typedef struct agent_context agent_context_t;

/* Simple thread management functions */
int start_all_threads(agent_context_t *ctx);
void stop_all_threads(agent_context_t *ctx);

#endif /* COOPER_THREAD_MANAGER_H */