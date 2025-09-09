/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROC_MEM_H
#define PROC_MEM_H

#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>

uint64_t get_process_memory();
uint64_t get_thread_memory(pid_t native_tid);

#endif /* PROC_MEM_H */