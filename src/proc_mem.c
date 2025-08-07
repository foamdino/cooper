/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "proc_mem.h"

/* Process-wide mem tracking for linux */
uint64_t
get_process_memory()
{
#ifdef __linux__
	int proc_fd = -1;
	char buf[4096];

	/* Open procfs file */
	char proc_path[64];
	snprintf(proc_path, sizeof(proc_path), "/proc/%d/statm", getpid());
	proc_fd = open(proc_path, O_RDONLY);

	if (proc_fd < 0)
		return 0;

	ssize_t bytes_read = read(proc_fd, buf, sizeof(buf) - 1);
	close(proc_fd);
	if (bytes_read <= 0)
		return 0;

	buf[bytes_read] = '\0';

	/* Parse resident set size */
	unsigned long vm_size, rss;
	int res = sscanf(buf, "%lu %lu", &vm_size, &rss);

	if (res != 2)
		return 0;

	/* Convert from pages to bytes */
	return (uint64_t)(rss * sysconf(_SC_PAGESIZE));
#else
	return 0; /* Not on linux, so 0 */
#endif
}

/* Thread specific tracking for linux */
uint64_t
get_thread_memory(pid_t native_tid)
{
#ifdef __linux__
	/* Get thread-specific mem info */
	char proc_path[128];
	char buf[4096];

	snprintf(
	    proc_path, sizeof(proc_path), "/proc/%d/task/%d/statm", getpid(), native_tid);

	int fd = open(proc_path, O_RDONLY);
	if (fd < 0)
		return 0;

	ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (bytes_read <= 0)
		return 0;

	buf[bytes_read] = '\0';

	/* parse values */
	unsigned long vm_size, rss;
	if (sscanf(buf, "%lu %lu", &vm_size, &rss) != 2)
		return 0;

	/* Convert from pages to bytes */
	uint64_t memory_bytes = (uint64_t)(rss * sysconf(_SC_PAGESIZE));
	return memory_bytes;
#else
	return 0; /* Not on linux, so 0 */
#endif
}