/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef THREAD_UTIL_H
#define THREAD_UTIL_H

#include <pthread.h>
#include <errno.h>
#include <unistd.h>

/**
 * Helper function to join a thread with timeout
 *
 * @param thread    Thread ID to join
 * @param timeout   Timeout in seconds
 * @return          0 on success, error code on failure
 */
int safe_thread_join(pthread_t thread, int timeout);

#endif /* THREAD_UTIL_H */