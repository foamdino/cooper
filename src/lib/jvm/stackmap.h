/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STACKMAP_H
#define STACKMAP_H

#include "class.h"
#include "../arena.h"

typedef enum verification_type verification_type_e;

/* Verification types from JVMS §4.10.1.2 */
enum verification_type
{
	ITEM_Top               = 0,
	ITEM_Integer           = 1,
	ITEM_Float             = 2,
	ITEM_Double            = 3, /* Takes 2 slots */
	ITEM_Long              = 4, /* Takes 2 slots */
	ITEM_Null              = 5,
	ITEM_UninitializedThis = 6,
	ITEM_Object            = 7,
	ITEM_Uninitialized     = 8 /* Has offset */
};

#endif /* STACKMAP_H */