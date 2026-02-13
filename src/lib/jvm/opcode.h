/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_OPCODE_H
#define JVM_OPCODE_H

#include "class.h"
#include "opcode.def"

typedef enum opcode opcode_e;

/* Opcode flags for stack effect metadata (bitmask) */
#define NEEDS_CP    0x01 /* Requires constant pool lookup for type resolution */
#define VARIABLE    0x02 /* Complex/variable behavior, needs manual handler */
#define USES_LOCALS 0x04 /* Reads or writes local variables */
#define STACK_DUP   0x08 /* Stack duplication/manipulation operation */
#define IS_RETURN   0x10 /* Method return instruction */
#define IS_THROW    0x20 /* Throws exception (athrow) */

enum opcode
{
#define OPCODE(                                                                          \
    val, name, len, is_branch, pop_cnt, push_cnt, pop_types, push_types, flags)          \
	OP_##name = val,
#include "opcode.def"
#undef OPCODE
};

/* Lookup tables */
extern const char *MNEMONIC[256];
extern const u1 INSTRUCTION_LEN[256];
extern const u1 IS_BRANCH[256];
extern const int OPCODE_POP_COUNT[256];
extern const int OPCODE_PUSH_COUNT[256];
extern const char *OPCODE_POP_TYPES[256];
extern const char *OPCODE_PUSH_TYPES[256];
extern const int OPCODE_FLAGS[256];

u4 get_inst_len(const u1 *code, u4 pc, u4 code_len);

#endif /* JVM_OPCODE_H */