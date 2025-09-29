/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "opcode.h"

// static inline u4 read_u4(const u1 *data)
// {
//     return ((u4)data[0] << 24) | ((u4)data[1] << 16) |
//            ((u4)data[2] << 8) | data[3];
// }

const char *MNEMONIC[256] = {
#define OPCODE(val, name, len, is_branch) [val] = #name,
#include "opcode.def"
#undef OPCODE
};

const u1 INSTRUCTION_LEN[256] = {
#define OPCODE(val, name, len, is_branch) [val] = len,
#include "opcode.def"
#undef OPCODE
};

const u1 IS_BRANCH[256] = {
#define OPCODE(val, name, len, is_branch) [val] = is_branch,
#include "opcode.def"
#undef OPCODE
};

/* https://docs.oracle.com/javase/specs/jvms/se6/html/Instructions2.doc14.html */
static u4
get_switch_inst_len(const u1 *code, u4 pc)
{
	u1 opcode = code[pc];

	/* Check if opcode is switch */
	if (opcode != 0xaa && opcode != 0xab)
		return 0;

	/* Calculate padding */
	u4 pad    = (4 - ((pc + 1) % 4)) % 4;
	u4 offset = pc + 1 + pad;

	if (opcode == 0xaa) /* tableswitch */
	{
		/* Read low and high values */
		u4 low  = read_u4(&code[offset + 4]);
		u4 high = read_u4(&code[offset + 8]);

		/* Length = 1 (opcode) + padding + 12 (default+low+high) + (high-low+1)*4
		 */
		return 1 + pad + 12 + ((high - low + 1) * 4);
	}
	else /* lookupswitch (0xab) */
	{
		/* Read npairs val */
		u4 npairs = read_u4(&code[offset + 4]);

		/* Length = 1 (opcode) + padding + 8 (default+npairs) + npairs*8 */
		return 1 + pad + 8 + (npairs * 8);
	}
}

/**
 * The JVM has certain variable length instructions
 * which cannot be looked up - this function handles these cases
 */
u4
get_inst_len(const u1 *code, u4 pc, u4 code_len)
{
	if (pc >= code_len)
		return 0;

	u1 opcode = code[pc];
	switch (opcode)
	{
		case 0xaa: /* tableswitch */
		case 0xab: /* lookupswitch */
			return get_switch_inst_len(code, pc);

		case 0xc4: /* wide */
			/* Wide modifies the next instruction */
			if (pc + 1 >= code_len)
				return 0;

			u1 next_opcode = code[pc + 1];
			if (next_opcode == 0x84) /* iinc */
				return 6;        /* wide iinc has opcdoe + 5 bytes */
			else
				return 4; /* wide load/store has + 3 bytes */
	}

	/* Simple lookup case */
	return INSTRUCTION_LEN[opcode];
}