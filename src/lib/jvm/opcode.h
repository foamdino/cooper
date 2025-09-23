/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_OPCODE_H
#define JVM_OPCODE_H

#include "class.h"

const u1 INSTRUCTION_LENGTHS[256] = {
    1, /* 0x00 nop */
    1, /* 0x01 aconst_null */
    1, /* 0x02 iconst_m1 */

};

#endif /* JVM_OPCODE_H */