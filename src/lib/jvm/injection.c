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

static bytecode_result_e
inject_method_bytecode(arena_t *arena,
                       class_file_t *cf,
                       method_info_t *method,
                       u2 entry_method_ref,
                       u2 exit_method_ref,
                       u2 class_name_index,
                       u2 method_name_index)
{

	assert(arena != NULL);
	assert(cf != NULL);
	assert(method != NULL);

	/* Find code attr */
	attr_info_t *code_attr = NULL;
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);
		if (attr_name && strcmp(attr_name, "Code") == 0)
		{
			code_attr = &method->attributes[i];
			break;
		}
	}

	/* Abstract or native method - skip */
	if (!code_attr)
		return BYTECODE_SUCCESS;

	/* Parse the existing Code attribute
	https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.3
	Code_attribute {
	    u2 attribute_name_index;
	    u4 attribute_length;
	    u2 max_stack;
	    u2 max_locals;
	    u4 code_length;
	    u1 code[code_length];
	    u2 exception_table_length;
	    {   u2 start_pc;
	        u2 end_pc;
	        u2 handler_pc;
	        u2 catch_type;
	    } exception_table[exception_table_length];
	    u2 attributes_count;
	    attribute_info attributes[attributes_count];
	}
	*/
	int offset          = 0;
	const u1 *code_data = code_attr->info;
	u2 max_stack        = read_u2_and_advance(code_data, &offset);
	u2 max_locals       = read_u2_and_advance(code_data, &offset);
	u4 code_len         = read_u4_and_advance(code_data, &offset);
	/* Beginning of byte array containing the method */
	const u1 *existing_code = &code_data[offset];
	offset += code_len;

	/* Skip exception table and atributes for now */
	u2 exception_table_len = read_u2_and_advance(code_data, &offset);
	/* Each exception entry is 8 bytes */
	offset += exception_table_len * 8;

	u2 code_attributes_count = read_u2_and_advance(code_data, &offset);

	/* Skip code attributes */
	for (u2 i = 0; i < code_attributes_count; i++)
	{
		offset += 2; /* attribute_name_index */
		u4 attr_len = read_u4_and_advance(code_data, &offset);
		offset += attr_len;
	}

	// TODO refactor this into a function?
	/* Build entry injection bytecode:
	 * ldc_w #class_name_index    (3 bytes)
	 * ldc_w #method_name_index   (3 bytes)
	 * ldc_w #method_descriptor   (3 bytes)
	 * invokestatic #entry_methodref (3 bytes)
	 * Total: 12 bytes
	 */
	u1 entry_injection[12] = {
	    0x13,
	    (u1)(class_name_index >> 8),
	    (u1)(class_name_index & 0xFF), /* ldc_w class_name */
	    0x13,
	    (u1)(method_name_index >> 8),
	    (u1)(method_name_index & 0xFF), /* ldc_w method_name */
	    0x13,
	    (u1)(method->descriptor_index >> 8),
	    (u1)(method->descriptor_index & 0xFF), /* ldc_w method_descriptor */
	    0xB8,
	    (u1)(entry_method_ref >> 8),
	    (u1)(entry_method_ref & 0xFF) /* invokestatic entry_method */
	};

	/* Build exit injection for return instructions:
	 * Similar to entry but for exit callback
	 */
	u1 exit_injection[12] = {
	    0x13,
	    (u1)(class_name_index >> 8),
	    (u1)(class_name_index & 0xFF), /* ldc_w class_name */
	    0x13,
	    (u1)(method_name_index >> 8),
	    (u1)(method_name_index & 0xFF), /* ldc_w method_name */
	    0x13,
	    (u1)(method->descriptor_index >> 8),
	    (u1)(method->descriptor_index & 0xFF), /* ldc_w method_descriptor */
	    0xB8,
	    (u1)(exit_method_ref >> 8),
	    (u1)(exit_method_ref & 0xFF) /* invokestatic exit_method */
	};

	/* Calculate new size - estimate */
	u4 estimated_new_sz = code_len + sizeof(entry_injection);

	/* Scan for return instructions to inject exit calls */
	u4 return_count = 0;
	for (u4 i = 0; i < code_len; i++)
	{
		u1 opcode = existing_code[i];
		if (opcode == 0xB1 || /* return */
		    opcode == 0xAC || /* ireturn */
		    opcode == 0xAD || /* lreturn */
		    opcode == 0xAE || /* freturn */
		    opcode == 0xAF || /* dreturn */
		    opcode == 0xB0)
		{ /* areturn */
			return_count++;
		}
	}

	estimated_new_sz += return_count * sizeof(exit_injection);

	/* Create new code buffer */
	u1 *new_code = arena_alloc(arena, estimated_new_sz);
	if (!new_code)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u4 new_code_pos = 0;

	/* Inject entry tracking at method start */
	memcpy(&new_code[new_code_pos], entry_injection, sizeof(entry_injection));
	new_code_pos += sizeof(entry_injection);

	/* Copy exiting bytecode,
	injecting the exit calls before returns */
	for (u4 i = 0; i < code_len; i++)
	{
		u1 opcode = existing_code[i];
		/* Check if opcode is a return */
		if (opcode == 0xB1 || /* return */
		    opcode == 0xAC || /* ireturn */
		    opcode == 0xAD || /* lreturn */
		    opcode == 0xAE || /* freturn */
		    opcode == 0xAF || /* dreturn */
		    opcode == 0xB0)   /* areturn */
		{
			/* inject exit tracking */
			memcpy(&new_code[new_code_pos],
			       exit_injection,
			       sizeof(exit_injection));
			new_code_pos += sizeof(exit_injection);
		}

		/* Copy original instruction */
		new_code[new_code_pos++] = opcode;

		/* Handle instructions with operands
		simplified for common cases
		TODO: Complete instruction parsing for precise operand handling
		*/
		switch (opcode)
		{
			case 0x10: /* bipush */
			case 0x12: /* ldc */
				new_code[new_code_pos++] =
				    existing_code[++i]; /* 1 operand byte */
				break;
			case 0x11: /* sipush */
			case 0x13: /* ldc_w */
			case 0x14: /* ldc2_w */
				new_code[new_code_pos++] =
				    existing_code[++i]; /*2 operand byte */
				new_code[new_code_pos++] = existing_code[++i];
				break;
				/* Add more operand handling as required... */
		}
	}

	u4 final_new_code_len = new_code_pos;

	/* Create new Code attribute */
	u4 new_attr_len = 12 + final_new_code_len;
	/* Code attr header + new code + empty exception/attr tables */
	u1 *new_attr_data = arena_alloc(arena, new_attr_len);
	if (!new_attr_data)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int attr_offset = 0;
	/* We need to increase the stack for our code */
	write_u2_and_advance(new_attr_data, &attr_offset, max_stack + 3);
	write_u2_and_advance(new_attr_data, &attr_offset, max_locals);
	write_u4_and_advance(new_attr_data, &attr_offset, final_new_code_len);
	memcpy(&new_attr_data[attr_offset], new_code, final_new_code_len);
	attr_offset += final_new_code_len;

	/* Empty exception table for now */
	write_u2_and_advance(new_attr_data, &offset, 0); /* exception_table_len */
	write_u2_and_advance(new_attr_data, &offset, 0); /* attributes_count */

	/* Update the method's Code attribute */
	code_attr->info             = new_attr_data;
	code_attr->attribute_length = new_attr_len;

	return BYTECODE_SUCCESS;
}

bytecode_result_e
injection_add_method_tracking(arena_t *arena,
                              class_file_t *cf,
                              injection_config_t *config)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(config != NULL);

	/* Get class name for callbacks */
	const char *class_name = bytecode_get_class_name(cf);
	if (!class_name)
		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;

	u2 class_name_idx = injection_find_or_add_utf8_constant(arena, cf, class_name);
	if (class_name_idx == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add required constant pool entries */
	u2 entry_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, config->callback_class, config->entry_method, config->entry_sig);

	if (entry_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 exit_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, config->callback_class, config->exit_method, config->exit_sig);

	if (entry_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	size_t methods_modified = 0;
	/* Now inject the tracking into all methods */
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *method_name = bytecode_get_method_name(cf, i);
		/* Inject into every method apart from ctor */
		if (method_name && strcmp(method_name, "<clinit>") != 0)
		{
			u2 method_name_idx =
			    injection_find_or_add_utf8_constant(arena, cf, method_name);

			if (method_name_idx == 0)
				continue;

			bytecode_result_e res = inject_method_bytecode(arena,
			                                               cf,
			                                               &cf->methods[i],
			                                               entry_methodref,
			                                               exit_methodref,
			                                               class_name_idx,
			                                               method_name_idx);

			if (res != BYTECODE_SUCCESS)
				return res;

			methods_modified++;
		}
	}

	return BYTECODE_SUCCESS;
}