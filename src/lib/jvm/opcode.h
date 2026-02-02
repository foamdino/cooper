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

enum opcode
{
#define OPCODE(val, name, len, is_branch) OP_##name = val,
#include "opcode.def"
#undef OPCODE
};

extern const char *MNEMONIC[256];
extern const u1 INSTRUCTION_LEN[256];
extern const u1 IS_BRANCH[256];

u4 get_inst_len(const u1 *code, u4 pc, u4 code_len);

#endif /* JVM_OPCODE_H */