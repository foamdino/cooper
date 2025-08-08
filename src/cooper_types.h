/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_TYPES_H
#define COOPER_TYPES_H

#include <stddef.h>

typedef struct package_filter package_filter_t;

/* Package filter configuration */
struct package_filter
{
	char **include_packages;
	size_t *package_lengths;
	size_t num_packages;
};

/* Other shared types can go here */

#endif /* COOPER_TYPES_H */