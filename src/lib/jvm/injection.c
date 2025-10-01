/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdio.h>
#include "injection.h"

bytecode_result_e
injection_find_or_add_constant(arena_t *arena,
                               class_file_t *cf,
                               const constant_spec_t *spec,
                               u2 *out_index)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(spec != NULL);
	assert(out_index != NULL);

	/* Search for existing constant */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag != spec->tag)
			continue;

		/* Tag matches, does the content also match */
		int matches = 0;
		switch (spec->tag)
		{
			case CONSTANT_Utf8:
				const char *existing =
				    (const char *)cf->constant_pool[i].info.utf8.bytes;
				matches = (existing
				           && strcmp(existing, spec->data.utf8.str) == 0);
				break;

			case CONSTANT_String:
				matches = (cf->constant_pool[i].info.string
				           == spec->data.string.utf8_idx);
				break;

			case CONSTANT_Class:
				matches = (cf->constant_pool[i].info.class_info.name_index
				           == spec->data.class_info.name_idx);
				break;

			case CONSTANT_NameAndType:
				matches =
				    (cf->constant_pool[i].info.name_and_type.name_index
				         == spec->data.name_and_type.name_idx
				     && cf->constant_pool[i]
				                .info.name_and_type.descriptor_index
				            == spec->data.name_and_type.descriptor_idx);
				break;

			case CONSTANT_Methodref:
				matches =
				    (cf->constant_pool[i].info.methodref.class_index
				         == spec->data.methodref.class_idx
				     && cf->constant_pool[i]
				                .info.methodref.name_and_type_index
				            == spec->data.methodref.name_and_type_idx);
				break;

			default:
				return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
		}

		if (matches)
		{
			*out_index = i;
			return BYTECODE_SUCCESS;
		}
	}

	/* We didn't find the constant already */
	u2 new_cnt = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_cnt * sizeof(constant_pool_info_t));

	if (!new_pool)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Copy over existing entries / info */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Create the new entry based on tag, place at end of pool */
	u2 new_idx            = cf->constant_pool_count;
	new_pool[new_idx].tag = spec->tag;

	switch (spec->tag)
	{
		case CONSTANT_Utf8:
			size_t len                         = strlen(spec->data.utf8.str);
			new_pool[new_idx].info.utf8.length = len;
			new_pool[new_idx].info.utf8.bytes  = arena_alloc(arena, len + 1);

			if (!new_pool[new_idx].info.utf8.bytes)
				return BYTECODE_ERROR_MEMORY_ALLOCATION;

			strcpy((char *)new_pool[new_idx].info.utf8.bytes,
			       spec->data.utf8.str);
			break;

		case CONSTANT_String:
			new_pool[new_idx].info.string = spec->data.string.utf8_idx;
			break;

		case CONSTANT_Class:
			new_pool[new_idx].info.class_info.name_index =
			    spec->data.class_info.name_idx;
			break;

		case CONSTANT_NameAndType:
			new_pool[new_idx].info.name_and_type.name_index =
			    spec->data.name_and_type.name_idx;
			new_pool[new_idx].info.name_and_type.descriptor_index =
			    spec->data.name_and_type.descriptor_idx;
			break;

		case CONSTANT_Methodref:
			new_pool[new_idx].info.methodref.class_index =
			    spec->data.methodref.class_idx;
			new_pool[new_idx].info.methodref.name_and_type_index =
			    spec->data.methodref.name_and_type_idx;
			break;

		default:
			return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
	}

	/* Update class file */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_cnt;

	*out_index = new_idx;
	return BYTECODE_SUCCESS;
}

bytecode_result_e
injection_find_or_add_utf8_constant(arena_t *arena,
                                    class_file_t *cf,
                                    const char *str,
                                    u2 *out_index)
{
	constant_spec_t spec = {.tag = CONSTANT_Utf8, .data.utf8.str = str};
	return injection_find_or_add_constant(arena, cf, &spec, out_index);
}

bytecode_result_e
injection_find_or_add_class_constant(arena_t *arena,
                                     class_file_t *cf,
                                     const char *class_name,
                                     u2 *out_index)
{
	u2 class_name_index;
	bytecode_result_e rc =
	    injection_find_or_add_utf8_constant(arena, cf, class_name, &class_name_index);

	if (rc != BYTECODE_SUCCESS)
		return rc;

	constant_spec_t spec = {.tag                      = CONSTANT_Class,
	                        .data.class_info.name_idx = class_name_index};
	return injection_find_or_add_constant(arena, cf, &spec, out_index);
}

bytecode_result_e
injection_find_or_add_string_constant(arena_t *arena,
                                      class_file_t *cf,
                                      const char *str,
                                      u2 *out_index)
{
	u2 utf8_index;
	bytecode_result_e rc =
	    injection_find_or_add_utf8_constant(arena, cf, str, &utf8_index);

	if (rc != BYTECODE_SUCCESS)
		return rc;

	constant_spec_t spec = {.tag                  = CONSTANT_String,
	                        .data.string.utf8_idx = utf8_index};
	return injection_find_or_add_constant(arena, cf, &spec, out_index);
}

bytecode_result_e
injection_find_or_add_methodref_constant(arena_t *arena,
                                         class_file_t *cf,
                                         const char *class_name,
                                         const char *method_name,
                                         const char *method_sig,
                                         u2 *out_index)
{
	/* Get or create dependencies */
	u2 class_idx;
	bytecode_result_e rc =
	    injection_find_or_add_class_constant(arena, cf, class_name, &class_idx);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	u2 name_idx;
	rc = injection_find_or_add_utf8_constant(arena, cf, method_name, &name_idx);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	u2 desc_idx;
	rc = injection_find_or_add_utf8_constant(arena, cf, method_sig, &desc_idx);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	/* Find or create NameAndType */
	u2 name_type_idx;
	constant_spec_t nat_spec = {.tag                         = CONSTANT_NameAndType,
	                            .data.name_and_type.name_idx = name_idx,
	                            .data.name_and_type.descriptor_idx = desc_idx};
	rc = injection_find_or_add_constant(arena, cf, &nat_spec, &name_type_idx);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	/* Create Methodref */
	constant_spec_t spec = {.tag                              = CONSTANT_Methodref,
	                        .data.methodref.class_idx         = class_idx,
	                        .data.methodref.name_and_type_idx = name_type_idx};
	return injection_find_or_add_constant(arena, cf, &spec, out_index);
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

static bytecode_result_e
bb_ensure_capacity(bytecode_builder_t *bb, u4 needed)
{
	if (bb->len + needed <= bb->capacity)
		return BYTECODE_SUCCESS;

	/* grow capacity */
	u4 new_capacity = bb->capacity * 2;
	while (new_capacity < bb->len + needed)
		new_capacity *= 2;

	u1 *new_buf = arena_alloc(bb->arena, new_capacity);
	if (!new_buf)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Copy over existing data */
	memcpy(new_buf, bb->buf, bb->len);
	bb->buf      = new_buf;
	bb->capacity = new_capacity;

	return BYTECODE_SUCCESS;
}

bytecode_result_e
bb_add_template(bytecode_builder_t *bb,
                const bytecode_template_t *tmpl,
                const u2 indices[])
{
	if (bb_ensure_capacity(bb, tmpl->len) != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

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
	return BYTECODE_SUCCESS;
}

bytecode_result_e
bb_add_original_chunk(bytecode_builder_t *bb,
                      const u1 *original_code,
                      u4 start_offset,
                      u4 chunk_len)
{
	if (bb_ensure_capacity(bb, chunk_len) != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

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

	return BYTECODE_SUCCESS;
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

bytecode_result_e
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
	if (bb_ensure_capacity(bb, inst_len + (new_pad - pad)) != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Write the opcode */
	bb->buf[bb->len++] = opcode;

	/* Write padding */
	for (u4 i = 0; i < new_pad; i++)
		bb->buf[bb->len++] = 0;

	u4 data_offset = original_pc + 1 + pad;

	/* Read and remap default offset */
	u4 default_offset  = read_u4(&original_code[data_offset]);
	u4 original_target = original_pc + default_offset;
	u4 new_target      = bb_map_pc(bb, original_target);
	u4 new_default     = (new_target - new_pc);
	write_u4(&bb->buf[bb->len], new_default);
	bb->len += 4; /* advance the 4 bytes we just wrote */

	if (opcode == OP_tableswitch) /* tableswitch */
	{
		u4 low  = read_u4(&original_code[data_offset + 4]);
		u4 high = read_u4(&original_code[data_offset + 8]);

		write_u4(&bb->buf[bb->len], low);
		bb->len += 4;
		write_u4(&bb->buf[bb->len], high);
		bb->len += 4;

		/* Validate: interpret as signed for range check */
		i4 low_signed  = (i4)low;
		i4 high_signed = (i4)high;
		if (high_signed < low_signed)
			return BYTECODE_ERROR_INVALID_BYTECODE; /* Malformed bytecode */

		/* Now safe to compute range as unsigned */
		u4 num_cases = (high - low) + 1;

		/* Sanity check: tableswitch can't have more than ~65K cases */
		if (num_cases > 65536)
			return BYTECODE_ERROR_INVALID_BYTECODE; /* Suspiciously large or
			                                           malformed */

		/* Remap jump offsets */
		for (u4 i = 0; i < num_cases; i++)
		{
			u4 offset = read_u4(&original_code[data_offset + 12 + (i * 4)]);
			original_target = original_pc + offset;
			new_target      = bb_map_pc(bb, original_target);
			u4 new_offset   = (new_target - new_pc);
			write_u4(&bb->buf[bb->len], new_offset);
			bb->len += 4;
		}
	}
	else /* lookupswitch */
	{
		/* lookupswitch <0-3 byte pad\>
		        defaultbyte1 defaultbyte2 defaultbyte3 defaultbyte4
		        npairs1 npairs2 npairs3 npairs4 match-offset pairs...
		*/
		u4 npairs = read_u4(&original_code[data_offset + 4]);

		write_u4(&bb->buf[bb->len], npairs);
		bb->len += 4;

		/* Remap match-offset pairs */
		for (u4 i = 0; i < npairs; i++)
		{
			u4 match  = read_u4(&original_code[data_offset + 8 + (i * 8)]);
			u4 offset = read_u4(&original_code[data_offset + 12 + (i * 8)]);

			write_u4(&bb->buf[bb->len], match);
			bb->len += 4;

			original_target = original_pc + offset;
			new_target      = bb_map_pc(bb, original_target);
			u4 new_offset   = (new_target - new_pc);
			write_u4(&bb->buf[bb->len], new_offset);
			bb->len += 4;
		}
	}

	return BYTECODE_SUCCESS;
}

bytecode_result_e
bb_add_original_with_exit_injection(bytecode_builder_t *bb,
                                    const u1 *original_code,
                                    u4 start_offset,
                                    u4 chunk_len,
                                    const bytecode_template_t *exit_template,
                                    const u2 exit_indices[])
{
	u4 original_pos = 0;

	while (original_pos < chunk_len)
	{
		u1 opcode = original_code[start_offset + original_pos];
		u1 inst_len =
		    get_inst_len(&original_code[start_offset], original_pos, chunk_len);

		if (inst_len == 0 || original_pos + inst_len > chunk_len)
		{
			printf("ERROR: invalid instruction at offset %u (opcode=0x%02X, "
			       "len=%u)\n",
			       original_pos,
			       opcode,
			       inst_len);
			return BYTECODE_ERROR_INVALID_BYTECODE;
		}

		/* Record chunk mapping */
		if (bb->chunk_cnt < 32)
		{
			pc_chunk_t *chunk = &bb->chunks[bb->chunk_cnt];
			/* Current PC */
			chunk->original_start = start_offset + original_pos;
			/* Single PC */
			chunk->original_end = start_offset + original_pos + 1;
			/* Where it goes in new byte code */
			chunk->new_start = bb->len;
			/* Unused */
			chunk->new_len = 0;
			bb->chunk_cnt++;
		}

		if (opcode == OP_return || opcode == OP_ireturn || opcode == OP_lreturn
		    || opcode == OP_freturn || opcode == OP_dreturn
		    || opcode == OP_areturn)
		{
			if (bb_add_template(bb, exit_template, exit_indices)
			    != BYTECODE_SUCCESS)
				return BYTECODE_ERROR_MEMORY_ALLOCATION;
		}

		/* Handle variable length switches */
		if (opcode == OP_tableswitch || opcode == OP_lookupswitch)
		{
			if (bb_add_switch_inst(
				bb, &original_code[start_offset], original_pos, inst_len)
			    != BYTECODE_SUCCESS)
				return BYTECODE_ERROR_INVALID_BYTECODE;
		}
		else if (IS_BRANCH[opcode] == 1) /* 2 byte offset */
		{
			if (bb_ensure_capacity(bb, 3) != BYTECODE_SUCCESS)
				return BYTECODE_ERROR_MEMORY_ALLOCATION;

			u2 offset =
			    read_u2(&original_code[start_offset + original_pos + 1]);
			u4 original_target = start_offset + original_pos + offset;
			u4 new_pc          = bb->len;
			u4 new_target      = bb_map_pc(bb, original_target);
			u2 new_offset      = (u2)(new_target - new_pc);

			bb->buf[bb->len++] = opcode;
			bb->buf[bb->len++] = (u1)(new_offset >> 8);
			bb->buf[bb->len++] = (u1)(new_offset & 0xff);
		}
		else if (IS_BRANCH[opcode] == 2) /* 4 byte offset */
		{
			if (bb_ensure_capacity(bb, 5) != BYTECODE_SUCCESS)
				return BYTECODE_ERROR_MEMORY_ALLOCATION;

			u4 offset =
			    read_u4(&original_code[start_offset + original_pos + 1]);
			u4 original_target = start_offset + original_pos + offset;
			u4 new_pc          = bb->len;
			u4 new_target      = bb_map_pc(bb, original_target);
			u4 new_offset      = new_target - new_pc;

			bb->buf[bb->len++] = opcode;
			write_u4(&bb->buf[bb->len], new_offset);
			bb->len += 4;
		}
		else
		{
			/* Copy original instruction */
			if (bb_ensure_capacity(bb, inst_len) != BYTECODE_SUCCESS)
				return BYTECODE_ERROR_MEMORY_ALLOCATION;

			memcpy(&bb->buf[bb->len],
			       &original_code[start_offset + original_pos],
			       inst_len);

			bb->len += inst_len;
		}

		original_pos += inst_len;
	}

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
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
static bytecode_result_e
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
	if (parse_code_attribute(code_attr, &code_info) != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_INVALID_BYTECODE;

	/* TODO Skip methods with StackMapTable -
	requires StackMapTable frame recalculation
	which is not yet implemented. See JVM spec §4.7.4 for details. */
	if (code_has_stackmap_table(cf, &code_info))
		return BYTECODE_SUCCESS;

	/* Build new bytecode */
	bytecode_builder_t *bb = bb_create(arena, code_info.code_length + 64);
	if (!bb)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 entry_indices[] = {
	    class_name_index, method_name_index, descriptor_index, entry_methodref};
	u2 exit_indices[] = {
	    class_name_index, method_name_index, descriptor_index, exit_methodref};

	/* Use template to add new method entry */
	if (bb_add_template(bb, &METHOD_TEMPLATE, entry_indices) != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add original code with exit injection */
	if (bb_add_original_with_exit_injection(bb,
	                                        code_info.bytecode,
	                                        0,
	                                        code_info.code_length,
	                                        &METHOD_TEMPLATE,
	                                        exit_indices)
	    != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add new Code attribute */
	if (create_new_code_attribute(arena, cf, method, bb, &code_info)
	    != BYTECODE_SUCCESS)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	return BYTECODE_SUCCESS;
}

bytecode_result_e
injection_add_method_tracking(arena_t *arena, class_file_t *cf, injection_config_t *cfg)
{
	const char *class_name = bytecode_get_class_name(cf);
	if (!class_name)
		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;

	u2 class_idx = 0;
	bytecode_result_e rc =
	    injection_find_or_add_string_constant(arena, cf, class_name, &class_idx);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	u2 entry_methodref = 0;
	rc                 = injection_find_or_add_methodref_constant(arena,
                                                      cf,
                                                      cfg->callback_class,
                                                      cfg->entry_method,
                                                      cfg->entry_sig,
                                                      &entry_methodref);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	u2 exit_methodref = 0;
	rc                = injection_find_or_add_methodref_constant(arena,
                                                      cf,
                                                      cfg->callback_class,
                                                      cfg->exit_method,
                                                      cfg->exit_sig,
                                                      &exit_methodref);
	if (rc != BYTECODE_SUCCESS)
		return rc;

	/* Inject */
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *method_name = bytecode_get_method_name(cf, i);

		/* ignore ctor */
		if (method_name && strcmp(method_name, "<clinit>") != 0)
		{
			u2 method_name_idx = 0;
			rc                 = injection_find_or_add_string_constant(
                            arena, cf, method_name, &method_name_idx);
			if (rc != BYTECODE_SUCCESS)
				continue;

			/* Get method descriptor */
			const char *method_descriptor = bytecode_get_utf8_constant(
			    cf, cf->methods[i].descriptor_index);
			if (!method_descriptor)
				continue;

			u2 descriptor_string_idx = 0;
			rc                       = injection_find_or_add_string_constant(
                            arena, cf, method_descriptor, &descriptor_string_idx);
			if (rc != BYTECODE_SUCCESS)
				continue;

			rc = inject_single_method(arena,
			                          cf,
			                          &cf->methods[i],
			                          entry_methodref,
			                          exit_methodref,
			                          class_idx,
			                          method_name_idx,
			                          descriptor_string_idx);

			if (rc != BYTECODE_SUCCESS)
				return rc;
		}
	}

	return BYTECODE_SUCCESS;
}
