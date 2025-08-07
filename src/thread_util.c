
/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "thread_util.h"

/**
 * Helper function to join a thread with timeout
 *
 * @param thread    Thread ID to join
 * @param timeout   Timeout in seconds
 * @return          0 on success, error code on failure
 */
int
safe_thread_join(pthread_t thread, int timeout)
{
	/* First try to join without any tricks (normal path) */
	int result = pthread_join(thread, NULL);
	if (result == 0)
	{
		return 0; /* Joined successfully */
	}

	/* If we can't join (thread might be detached or already joined) */
	if (result == EINVAL || result == ESRCH)
	{
		return result; /* Return the error code */
	}

	/* For threads that can't be joined immediately but timeout > 0 */
	if (timeout > 0)
	{
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += timeout;

		/* Sleep in small increments and retry joining */
		while (timeout > 0)
		{
			/* Sleep for 100ms at a time */
			usleep(100000);

			/* Try joining again */
			result = pthread_join(thread, NULL);
			if (result == 0)
			{
				return 0; /* Successfully joined */
			}

			/* If thread is invalid or already joined/detached, return */
			if (result == EINVAL || result == ESRCH)
			{
				return result;
			}

			/* Check if we've exceeded the timeout */
			struct timespec current;
			clock_gettime(CLOCK_REALTIME, &current);
			if (current.tv_sec >= ts.tv_sec && current.tv_nsec >= ts.tv_nsec)
			{
				break;
			}
		}
	}

	/* If we reach here, we couldn't join within the timeout period */
	return ETIMEDOUT;
}