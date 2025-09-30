/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdio.h>
#include "injection.h"

// TODO smush these into a single helper
// with a switch for tag, similar to the constant pool parsing
u2
injection_find_or_add_utf8_constant(arena_t *arena, class_file_t *cf, const char *str)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(str != NULL);

	/* Check if constant is present */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_Utf8)
		{
			const char *existing =
			    (const char *)cf->constant_pool[i].info.utf8.bytes;
			if (existing && strcmp(existing, str) == 0)
				return i;
		}
	}

	/* Not present, need to add */
	u2 new_count = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));

	// TODO fix this, we should use a param for output and a normal result code
	if (!new_pool)
		return 0;

	/* Copy the existing entries over */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Add new CONSTANT_Utf8 */
	u2 new_idx                         = cf->constant_pool_count;
	new_pool[new_idx].tag              = CONSTANT_Utf8;
	new_pool[new_idx].info.utf8.length = strlen(str);
	new_pool[new_idx].info.utf8.bytes  = arena_alloc(arena, strlen(str) + 1);
	if (!new_pool[new_idx].info.utf8.bytes)
		return 0; // TODO see other comment

	/* Copy the bytes */
	strcpy((char *)new_pool[new_idx].info.utf8.bytes, str);

	/* Update the class file constant pool */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_count;

	return new_idx;
}

u2
injection_find_or_add_string_constant(arena_t *arena, class_file_t *cf, const char *str)
{
	/* First, get or create the UTF8 constant */
	u2 utf8_index = injection_find_or_add_utf8_constant(arena, cf, str);
	if (utf8_index == 0)
		return 0;

	/* Check if String constant already exists */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_String)
		{
			if (cf->constant_pool[i].info.string == utf8_index)
				return i;
		}
	}

	/* Create new String constant */
	u2 new_size = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_size * sizeof(constant_pool_info_t));
	if (!new_pool)
		return 0;

	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	u2 new_index                    = cf->constant_pool_count;
	new_pool[new_index].tag         = CONSTANT_String;
	new_pool[new_index].info.string = utf8_index;

	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_size;

	return new_index;
}

u2
injection_find_or_add_class_constant(arena_t *arena,
                                     class_file_t *cf,
                                     const char *class_name)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(class_name != NULL);

	u2 name_idx = injection_find_or_add_utf8_constant(arena, cf, class_name);
	if (name_idx == 0)
		return 0;

	/* Check if this class constant exists */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_Class)
		{
			if (cf->constant_pool[i].info.class_info.name_index == name_idx)
				return i;
		}
	}

	/* Not present, need to add */
	u2 new_count = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));

	if (!new_pool)
		return 0;

	/* Copy the existing entries over */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Add new CONSTANT_Class*/
	u2 new_idx                                   = cf->constant_pool_count;
	new_pool[new_idx].tag                        = CONSTANT_Class;
	new_pool[new_idx].info.class_info.name_index = name_idx;

	/* Update the class file constant pool */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_count;

	return new_idx;
}

u2
injection_find_or_add_methodref_constant(arena_t *arena,
                                         class_file_t *cf,
                                         const char *class_name,
                                         const char *method_name,
                                         const char *method_sig)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(class_name != NULL);
	assert(method_name != NULL);
	assert(method_sig != NULL);

	/* Get the class constant */
	u2 class_idx = injection_find_or_add_class_constant(arena, cf, class_name);
	if (class_idx == 0)
		return 0;

	/* Get name and type constants */
	u2 name_idx = injection_find_or_add_utf8_constant(arena, cf, method_name);
	if (name_idx == 0)
		return 0;

	u2 desc_idx = injection_find_or_add_utf8_constant(arena, cf, method_sig);
	if (desc_idx == 0)
		return 0;

	/* Find or create the NameAndType constant */
	u2 name_type_idx = 0;
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_NameAndType)
		{
			if (cf->constant_pool[i].info.name_and_type.name_index == name_idx
			    && cf->constant_pool[i].info.name_and_type.descriptor_index
			           == desc_idx)
			{
				name_type_idx = i;
				break;
			}
		}
	}

	/* Create a new NameAndType constant as we couldn't find it */
	if (name_type_idx == 0)
	{
		u2 new_count = cf->constant_pool_count + 1;
		constant_pool_info_t *new_pool =
		    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));
		if (!new_pool)
			return 0;

		/* Copy the existing entries over */
		memcpy(new_pool,
		       cf->constant_pool,
		       cf->constant_pool_count * sizeof(constant_pool_info_t));

		name_type_idx               = cf->constant_pool_count;
		new_pool[name_type_idx].tag = CONSTANT_NameAndType;
		new_pool[name_type_idx].info.name_and_type.name_index       = name_idx;
		new_pool[name_type_idx].info.name_and_type.descriptor_index = desc_idx;

		cf->constant_pool       = new_pool;
		cf->constant_pool_count = new_count;
	}

	/* Check for methdoref */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_Methodref)
		{
			if (cf->constant_pool[i].info.methodref.class_index == class_idx
			    && cf->constant_pool[i].info.methodref.name_and_type_index
			           == name_type_idx)
				return i;
		}
	}

	/* Need to create methodref */
	u2 new_count = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));
	if (!new_pool)
		return 0;

	/* Copy the existing entries over */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Add new CONSTANT_Methodref */
	u2 new_idx                                           = cf->constant_pool_count;
	new_pool[new_idx].tag                                = CONSTANT_Methodref;
	new_pool[new_idx].info.methodref.class_index         = class_idx;
	new_pool[new_idx].info.methodref.name_and_type_index = name_type_idx;

	/* Update the class file constant pool */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_count;

	return new_idx;
}

bytecode_builder_t *
bb_create(arena_t *arena, u4 initial_capacity)
{
	bytecode_builder_t *bb = arena_alloc(arena, sizeof(bytecode_builder_t));

	if (!bb)
		return NULL;

	bb->arena     = arena;
	bb->capacity  = initial_capacity;
	bb->len       = 0;
	bb->chunk_cnt = 0;

	bb->buf = arena_alloc(arena, initial_capacity);
	if (!bb->buf)
		return NULL;

	return bb;
}

static int
bb_ensure_capacity(bytecode_builder_t *bb, u4 needed)
{
	if (bb->len + needed <= bb->capacity)
		return 0;

	/* grow capacity */
	u4 new_capacity = bb->capacity * 2;
	while (new_capacity < bb->len + needed)
		new_capacity *= 2;

	u1 *new_buf = arena_alloc(bb->arena, new_capacity);
	if (!new_buf)
		return 1;

	/* Copy over existing data */
	memcpy(new_buf, bb->buf, bb->len);
	bb->buf      = new_buf;
	bb->capacity = new_capacity;

	return 0;
}

int
bb_add_template(bytecode_builder_t *bb,
                const bytecode_template_t *tmpl,
                const u2 indices[])
{
	if (bb_ensure_capacity(bb, tmpl->len) != 0)
		return 1;

	/* Copy template bytes */
	memcpy(&bb->buf[bb->len], tmpl->bytes, tmpl->len);

	/* Substitute placeholders */
	for (u2 i = 0; i < tmpl->placeholder_cnt; i++)
	{
		u4 offset = bb->len + tmpl->placeholder_offsets[i];
		u2 idx    = indices[i];

		/* Write big endian */
		bb->buf[offset]     = (u1)(idx >> 8);
		bb->buf[offset + 1] = (u1)(idx & 0xFF);
	}

	bb->len += tmpl->len;
	return 0;
}

int
bb_add_original_chunk(bytecode_builder_t *bb,
                      const u1 *original_code,
                      u4 start_offset,
                      u4 chunk_len)
{
	if (bb_ensure_capacity(bb, chunk_len) != 0)
		return 1;

	if (bb->chunk_cnt < 32)
	{
		pc_chunk_t *chunk     = &bb->chunks[bb->chunk_cnt];
		chunk->original_start = start_offset;
		chunk->original_end   = start_offset + chunk_len;
		chunk->new_start      = bb->len;
		chunk->new_len        = chunk_len;
		bb->chunk_cnt++;
	}

	/* Copy the bytecode */
	memcpy(&bb->buf[bb->len], &original_code[start_offset], chunk_len);
	bb->len += chunk_len;

	return 0;
}

u4
bb_map_pc(const bytecode_builder_t *bb, u4 original_pc)
{
	u4 best_match = original_pc; /* fallback */

	for (u4 i = 0; i < bb->chunk_cnt; i++)
	{
		const pc_chunk_t *chunk = &bb->chunks[i];

		/* Exact match */
		if (chunk->original_start == original_pc)
			return chunk->new_start;

		/* Before target - could be best match */
		if (chunk->original_start < original_pc)
		{
			u4 offset  = original_pc - chunk->original_start;
			best_match = chunk->new_start + offset;
		}
	}

	return best_match;
}

int
bb_add_switch_inst(bytecode_builder_t *bb,
                   const u1 *original_code,
                   u4 original_pc,
                   u4 inst_len)
{
	u1 opcode  = original_code[original_pc];
	u4 pad     = (4 - ((original_pc + 1) % 4)) % 4;
	u4 new_pc  = bb->len;
	u4 new_pad = (4 - ((new_pc + 1) % 4)) % 4;

	/* Allocate space */
	if (bb_ensure_capacity(bb, inst_len + (new_pad - pad)) != 0)
		return 1;

	/* Write the opcode */
	bb->buf[bb->len++] = opcode;

	/* Write padding */
	for (u4 i = 0; i < new_pad; i++)
		bb->buf[bb->len++] = 0;

	u4 data_offset = original_pc + 1 + pad;

	/* Read and remap default offset */
	i4 default_offset  = (i4)read_u4(&original_code[data_offset]);
	u4 original_target = original_pc + default_offset;
	u4 new_target      = bb_map_pc(bb, original_target);
	i4 new_default     = (i4)(new_target - new_pc);
	write_i4(&bb->buf[bb->len], new_default);
	bb->len += 4; /* advance the 4 bytes we just wrote */

	if (opcode == OP_tableswitch) /* tableswitch */
	{
		i4 low  = (i4)read_u4(&original_code[data_offset + 4]);
		i4 high = (i4)read_u4(&original_code[data_offset + 8]);

		write_i4(&bb->buf[bb->len], low);
		bb->len += 4;
		write_i4(&bb->buf[bb->len], high);
		bb->len += 4;

		/* Remap jump offsets */
		for (i4 i = 0; i <= (high - low); i++)
		{
			i4 offset =
			    (i4)read_u4(&original_code[data_offset + 12 + (i * 4)]);
			original_target = original_pc + offset;
			new_target      = bb_map_pc(bb, original_target);
			i4 new_offset   = (i4)(new_target - new_pc);
			write_i4(&bb->buf[bb->len], new_offset);
			bb->len += 4;
		}
	}
	else /* lookupswitch */
	{
		/* lookupswitch <0-3 byte pad\>
		        defaultbyte1 defaultbyte2 defaultbyte3 defaultbyte4
		        npairs1 npairs2 npairs3 npairs4 match-offset pairs...
		*/
		i4 npairs = (i4)read_u4(&original_code[data_offset + 4]);

		write_i4(&bb->buf[bb->len], npairs);
		bb->len += 4;

		/* Remap match-offset pairs */
		for (i4 i = 0; i < npairs; i++)
		{
			i4 match = (i4)read_u4(&original_code[data_offset + 8 + (i * 8)]);
			i4 offset =
			    (i4)read_u4(&original_code[data_offset + 12 + (i * 8)]);

			write_i4(&bb->buf[bb->len], match);
			bb->len += 4;

			original_target = original_pc + offset;
			new_target      = bb_map_pc(bb, original_target);
			i4 new_offset   = (i4)(new_target - new_pc);
			write_i4(&bb->buf[bb->len], new_offset);
			bb->len += 4;
		}
	}

	return 0;
}

int
bb_add_branch_2byte(bytecode_builder_t *bb, const u1 *original_code, u4 original_pc)
{
	if (bb_ensure_capacity(bb, 3) != 0)
		return 1;

	u1 opcode = original_code[original_pc];
	i2 offset = (i2)read_u2(&original_code[original_pc + 1]);

	/* Calculate original target */
	u4 original_target = original_pc + offset;

	/* Remap to new target */
	u4 new_pc     = bb->len;
	u4 new_target = bb_map_pc(bb, original_target);
	i2 new_offset = (i2)(new_target - new_pc);

	/* Write the remapped instruction */
	bb->buf[bb->len++] = opcode;
	bb->buf[bb->len++] = (u1)(new_offset >> 8);
	bb->buf[bb->len++] = (u1)(new_offset & 0xff);

	return 0;
}

int
bb_add_branch_4byte(bytecode_builder_t *bb, const u1 *original_code, u4 original_pc)
{
	if (bb_ensure_capacity(bb, 5) != 0)
		return 1;

	u1 opcode = original_code[original_pc];
	i4 offset = (i4)read_u4(&original_code[original_pc + 1]);

	/* Calculate original target */
	u4 original_target = original_pc + offset;

	/* Remap to new target */
	u4 new_pc     = bb->len;
	u4 new_target = bb_map_pc(bb, original_target);
	i4 new_offset = (i4)(new_target - new_pc);

	/* Write remapped instruction */
	bb->buf[bb->len++] = opcode;
	write_i4(&bb->buf[bb->len], new_offset);
	bb->len += 4;

	return 0;
}

/* clang-format off */
int
bb_add_original_with_exit_injection(bytecode_builder_t *bb,
                                    const u1 *original_code,
                                    u4 start_offset,
                                    u4 chunk_len,
                                    const bytecode_template_t *exit_template,
                                    const u2 exit_indices[])
{
	u4 original_pos = 0;
	// u4 chunk_start  = bb->len;

	while (original_pos < chunk_len)
	{
		u1 opcode = original_code[start_offset + original_pos];
		u1 inst_len = get_inst_len(&original_code[start_offset], original_pos, chunk_len);

		if (inst_len == 0 || original_pos + inst_len > chunk_len)
		{
			printf("ERROR: invalid instruction at offset %u (opcode=0x%02X, len=%u)\n",
				original_pos, opcode, inst_len);
			return 1;
		}

		/* Record chunk mapping */
		if (bb->chunk_cnt < 32)
		{
			pc_chunk_t *chunk     = &bb->chunks[bb->chunk_cnt];
			/* Current PC */
			chunk->original_start = start_offset + original_pos;
			/* Single PC */
			chunk->original_end   = start_offset + original_pos + 1;
			/* Where it goes in new byte code */
			chunk->new_start      = bb->len;
			/* Unused */
			chunk->new_len        = 0;
			bb->chunk_cnt++;
		}

		if (opcode == OP_return || opcode == OP_ireturn || opcode == OP_lreturn ||
			opcode == OP_freturn || opcode == OP_dreturn || opcode == OP_areturn)
		{
			if (bb_add_template(bb, exit_template, exit_indices) != 0)
				return 1;
		}

		/* Handle variable length switches */
		if (opcode == OP_tableswitch || opcode == OP_lookupswitch)
		{
			if (bb_add_switch_inst(bb, 
					&original_code[start_offset], 
					original_pos, 
					inst_len) != 0)
				return 1;
		}
		else if (IS_BRANCH[opcode] == 1) /* 2 byte offset */
		{
			if (bb_add_branch_2byte(bb, 
					&original_code[start_offset], 
					original_pos) != 0)
				return 1;
		}
		else if (IS_BRANCH[opcode] == 2) /* 4 byte offset */
		{
			if (bb_add_branch_4byte(bb, 
					&original_code[start_offset], 
					original_pos) != 0)
				return 1;
		}
		else
		{
			/* Copy original instruction */
			if (bb_ensure_capacity(bb, inst_len) != 0)
				return 1;

			memcpy(&bb->buf[bb->len], 
               &original_code[start_offset + original_pos], 
               inst_len);
			
			bb->len += inst_len;
		}

		original_pos += inst_len;
	}

	return 0;
}
/* clang-format on */

static int
create_new_code_attribute(arena_t *arena,
                          class_file_t *cf,
                          method_info_t *method,
                          const bytecode_builder_t *bb,
                          const code_info_t *orig_info)
{
	/* Calculate size without StackMapTable */
	u4 exception_table_sz = orig_info->exception_table_length * 8;
	u4 new_attr_sz        = 2 + 2 + 4 + bb->len + 2 + exception_table_sz + 2;

	u1 *new_attr_data = arena_alloc(arena, new_attr_sz);
	if (!new_attr_data)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int offset = 0;

	/* Increase stack size for injected code */
	write_u2_and_advance(new_attr_data, &offset, orig_info->max_stack + 3);
	write_u2_and_advance(new_attr_data, &offset, orig_info->max_locals);
	write_u4_and_advance(new_attr_data, &offset, bb->len);

	/* Write modified bytecode */
	memcpy(&new_attr_data[offset], bb->buf, bb->len);
	offset += bb->len;

	/* Copy exception table with PC remapping */
	write_u2_and_advance(new_attr_data, &offset, orig_info->exception_table_length);

	if (orig_info->exception_table_length > 0)
	{
		const u1 *orig_table = orig_info->exception_table_data;
		int tbl_offset       = 0;

		for (u2 i = 0; i < orig_info->exception_table_length; i++)
		{
			u2 start_pc   = read_u2_and_advance(orig_table, &tbl_offset);
			u2 end_pc     = read_u2_and_advance(orig_table, &tbl_offset);
			u2 handler_pc = read_u2_and_advance(orig_table, &tbl_offset);
			u2 catch_type = read_u2_and_advance(orig_table, &tbl_offset);

			/* Remap PCs using bb_map_pc */
			write_u2_and_advance(
			    new_attr_data, &offset, bb_map_pc(bb, start_pc));
			write_u2_and_advance(
			    new_attr_data, &offset, bb_map_pc(bb, end_pc));
			write_u2_and_advance(
			    new_attr_data, &offset, bb_map_pc(bb, handler_pc));
			write_u2_and_advance(new_attr_data, &offset, catch_type);
		}
	}

	/* No attributes (removes StackMapTable) */
	write_u2_and_advance(new_attr_data, &offset, 0);

	/* Update method's Code attribute */
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);

		if (attr_name && strcmp(attr_name, "Code") == 0)
		{
			method->attributes[i].info             = new_attr_data;
			method->attributes[i].attribute_length = new_attr_sz;
			return BYTECODE_SUCCESS;
		}
	}

	return BYTECODE_ERROR_CORRUPT_METHODS;
}

static attr_info_t *
find_code_attribute(const class_file_t *cf, method_info_t *method)
{
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);

		if (attr_name && strcmp(attr_name, "Code") == 0)
			return &method->attributes[i];
	}

	return NULL;
}

/* Check if Code attribute has StackMapTable */
static int
code_has_stackmap_table(const class_file_t *cf, const code_info_t *info)
{
	if (info->attributes_count == 0)
		return 0;

	int offset          = 0;
	const u1 *attr_data = info->attributes_data;

	for (u2 i = 0; i < info->attributes_count; i++)
	{
		u2 name_index  = read_u2_and_advance(attr_data, &offset);
		u4 attr_length = read_u4_and_advance(attr_data, &offset);

		const char *attr_name = bytecode_get_utf8_constant(cf, name_index);
		if (attr_name && strcmp(attr_name, "StackMapTable") == 0)
			return 1; /* Found StackMapTable */

		offset += attr_length; /* Skip attribute data */
	}

	return 0; /* No StackMapTable found */
}

// TODO move to bytecode and expose in header
/* Parse a code_attr into a code_info struct */
static int
parse_code_attribute(const attr_info_t *code_attr, code_info_t *info)
{
	if (!code_attr || !info)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int offset        = 0;
	const u1 *data    = code_attr->info;
	info->max_stack   = read_u2_and_advance(data, &offset);
	info->max_locals  = read_u2_and_advance(data, &offset);
	info->code_length = read_u4_and_advance(data, &offset);
	info->bytecode    = &data[offset];
	offset += info->code_length;

	info->exception_table_length = read_u2_and_advance(data, &offset);
	info->exception_table_data   = &data[offset];
	/* Each exception entry is 8 bytes */
	offset += info->exception_table_length * 8;
	info->attributes_count = read_u2_and_advance(data, &offset);
	info->attributes_data  = &data[offset];

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
inject_single_method(arena_t *arena,
                     class_file_t *cf,
                     method_info_t *method,
                     u2 entry_methodref,
                     u2 exit_methodref,
                     u2 class_name_index,
                     u2 method_name_index,
                     u2 descriptor_index)
{
	attr_info_t *code_attr = find_code_attribute(cf, method);
	/* Nothing to do */
	if (!code_attr)
		return BYTECODE_SUCCESS;

	/* Parse the Code attr */
	code_info_t code_info;
	if (parse_code_attribute(code_attr, &code_info) != 0)
		return BYTECODE_ERROR_INVALID_BYTECODE;

	/* Skip methods with StackMapTable for now -
	they require complex PC remapping which we will handle at a later date */
	if (code_has_stackmap_table(cf, &code_info))
	{
		// printf("Skipping method with StackMapTable to avoid verification
		// errors");
		return BYTECODE_SUCCESS;
	}

	/* Build new bytecode */
	bytecode_builder_t *bb = bb_create(arena, code_info.code_length + 64);
	if (!bb)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 entry_indices[] = {
	    class_name_index, method_name_index, descriptor_index, entry_methodref};
	u2 exit_indices[] = {
	    class_name_index, method_name_index, descriptor_index, exit_methodref};

	/* Use template to add new method entry */
	if (bb_add_template(bb, &METHOD_TEMPLATE, entry_indices) != 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add original code with exit injection */
	if (bb_add_original_with_exit_injection(bb,
	                                        code_info.bytecode,
	                                        0,
	                                        code_info.code_length,
	                                        &METHOD_TEMPLATE,
	                                        exit_indices)
	    != 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add new Code attribute */
	if (create_new_code_attribute(arena, cf, method, bb, &code_info) != 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	return BYTECODE_SUCCESS;
}

bytecode_result_e
injection_add_method_tracking(arena_t *arena, class_file_t *cf, injection_config_t *cfg)
{
	const char *class_name = bytecode_get_class_name(cf);
	if (!class_name)
		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;

	u2 class_idx = injection_find_or_add_string_constant(arena, cf, class_name);
	if (class_idx == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 entry_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, cfg->callback_class, cfg->entry_method, cfg->entry_sig);

	if (entry_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 exit_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, cfg->callback_class, cfg->exit_method, cfg->exit_sig);

	if (exit_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Inject */
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *method_name = bytecode_get_method_name(cf, i);

		/* ignore ctor */
		if (method_name && strcmp(method_name, "<clinit>") != 0)
		{
			u2 method_name_idx =
			    injection_find_or_add_string_constant(arena, cf, method_name);
			if (method_name_idx == 0)
				continue;

			/* Get method descriptor */
			const char *method_descriptor = bytecode_get_utf8_constant(
			    cf, cf->methods[i].descriptor_index);
			if (!method_descriptor)
				continue;

			u2 descriptor_string_idx = injection_find_or_add_string_constant(
			    arena, cf, method_descriptor);
			if (descriptor_string_idx == 0)
				continue;

			bytecode_result_e res =
			    inject_single_method(arena,
			                         cf,
			                         &cf->methods[i],
			                         entry_methodref,
			                         exit_methodref,
			                         class_idx,
			                         method_name_idx,
			                         descriptor_string_idx);

			if (res != BYTECODE_SUCCESS)
				return res;
		}
	}

	return BYTECODE_SUCCESS;
}
