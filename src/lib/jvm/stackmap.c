/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "stackmap.h"
#include "src/lib/jvm/bytecode.h"
#include "src/lib/jvm/class.h"
#include <string.h>

/* Convert type code to verification type */
static verification_type_e
decode_type_code(char code)
{
	switch (code)
	{
		case 'I':
			return ITEM_Integer;
		case 'J':
			return ITEM_Long;
		case 'F':
			return ITEM_Float;
		case 'D':
			return ITEM_Double;
		case 'R':
			return ITEM_Object;
		default:
			return ITEM_Top;
	}
}

/* Push type onto stack */
static void
push_type(frame_state_t *frame, verification_type_e type, u2 cpool_index)
{
	frame->stack[frame->stack_cnt].type      = type;
	frame->stack[frame->stack_cnt].cpool_idx = cpool_index;
	frame->stack_cnt++;

	/* Long/Double take 2 slots */
	if (type == ITEM_Long || type == ITEM_Double)
	{
		frame->stack[frame->stack_cnt].type = ITEM_Top;
		frame->stack_cnt++;
	}
}

/* Pop type from stack */
static verification_type_e
pop_type(frame_state_t *frame)
{
	if (frame->stack_cnt == 0)
		return ITEM_Top;

	frame->stack_cnt--;
	verification_type_e type = frame->stack[frame->stack_cnt].type;

	/* Long/Double pop 2 slots */
	if (frame->stack_cnt > 0 && frame->stack[frame->stack_cnt - 1].type == ITEM_Long
	    || frame->stack[frame->stack_cnt - 1].type == ITEM_Double)
	{
		frame->stack_cnt--;
	}

	return type;
}

/*
 * Find an existing CONSTANT_Class entry whose name matches 'class_name'.
 * Returns the cpool index of the Class constant, or 0 if not found.
 *
 * This is a read-only lookup — unlike injection_find_or_add_class_constant,
 * it won't create a new constant pool entry.
 */
static u2
find_class_constant(const class_file_t *cf, const char *class_name, u2 len)
{
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag != CONSTANT_Class)
			continue;

		u2 name_idx = cf->constant_pool[i].info.class_info.name_index;
		if (name_idx == 0 || name_idx >= cf->constant_pool_count)
			continue;

		if (cf->constant_pool[name_idx].tag != CONSTANT_Utf8)
			continue;

		const char *name =
		    (const char *)cf->constant_pool[name_idx].info.utf8.bytes;
		u2 name_len = cf->constant_pool[name_idx].info.utf8.length;
		if (name && name_len == len && memcpy(name, class_name, len) == 0)
			return i;
	}
	return 0;
}

/*
 * Parse a single field type from the descriptor at position *pos.
 * Advances *pos past the consumed characters.
 * Fills in 'entry' with the verification type.
 *
 * Returns 0 on success, -1 on error.
 */
static int
parse_single_type(const class_file_t *cf,
                  const char *descriptor,
                  int *pos,
                  verification_type_entry_t *entry)
{
	entry->type      = ITEM_Top;
	entry->cpool_idx = 0;
	entry->offset    = 0;

	char c = descriptor[*pos];
	(*pos)++;

	switch (c)
	{
		case 'B': /* byte */
		case 'C': /* char */
		case 'I': /* int */
		case 'S': /* short */
		case 'Z': /* boolean */
			entry->type = ITEM_Integer;
			return 0;
		case 'F':
			entry->type = ITEM_Float;
			return 0;
		case 'J':
			entry->type = ITEM_Long;
			return 0;
		case 'D':
			entry->type = ITEM_Double;
			return 0;
		case 'L': {
			/* Object ref: L<classname>; */
			const char *start = &descriptor[*pos];
			const char *semi  = strchr(start, ';');
			if (!semi)
				return -1; /* malformed */

			u2 len           = (u2)(semi - start);
			entry->type      = ITEM_Object;
			entry->cpool_idx = find_class_constant(cf, start, len);
			*pos += len + 1; /* skip forward over classname + ';' */
			return 0;
		}
		case '[': {
			/* Array ref: consume the element type but the verification type
			 * is just ITEM_Object. We need the full array descriptor to find
			 * the class constant */
			int array_start = *pos - 1; /* include the '[' */

			/* Skip leading '[' for multidimensional arrays */
			while (descriptor[*pos] == '[')
				(*pos)++;

			/* Now consume the element type */
			char elem = descriptor[*pos];

			if (elem == 'L')
			{
				/* [Ljava/lang/String; - skip L....; */
				(*pos)++;
				const char *semi = strchr(&descriptor[*pos], ';');
				if (!semi)
					return -1; /* malformed */

				/* Advance pos past the entire type */
				*pos = (int)(semi - descriptor) + 1;
			}
			else
			{
				/* [I, [[D, etc - single char primitive, advance 1 */
				(*pos)++;
			}
			/*
			 * The full array descriptor e.g "[Ljava/lang/String;"
			 * We look for a matching CONSTANT_Class in the pool.
			 * If not found, cpool_idx stays 0 - the encoder will
			 * still emit ITEM_Object(0) which is valud for arrays
			 * that the JVM can infer from context.
			 */
			u2 array_len = (u2)(*pos - array_start);
			entry->type  = ITEM_Object;
			entry->cpool_idx =
			    find_class_constant(cf, &descriptor[array_start], array_len);
			return 0;
		}
		default:
			return -1; /* Unknown type */
	}
}

int
parse_method_descriptor(const class_file_t *cf,
                        const char *descriptor,
                        method_descriptor_t *result)
{
	assert(cf != NULL);
	assert(descriptor != NULL);
	assert(result != NULL);

	if (!cf || !descriptor || !result)
		return -1;

	memset(result, 0, sizeof(*result));

	int pos = 0;

	/* Must start with a '(' */
	assert(descriptor[pos] == '(');

	if (descriptor[pos] != '(')
		return -1;

	pos++;

	/* Parse parameter types */
	while (descriptor[pos] != ')')
	{
		/* Check unterminated, we've reached the end of the string but not seen a
		 * ')' */
		if (descriptor[pos] == '\0')
			return -1;

		/* Can only handle DESCRIPTOR_MAX_PARAMS
		 * https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.3.3
		 */
		if (result->params_cnt >= DESCRIPTOR_MAX_PARAMS)
			return -1;

		verification_type_entry_t entry;
		if (parse_single_type(cf, descriptor, &pos, &entry) != 0)
			return -1;

		/* Add new entry to method_descriptor */
		result->params[result->params_cnt++] = entry;

		/* Handle Long/Double which take 2 slots  - add ITEM_Top for the 2nd slot
		 */
		if (entry.type == ITEM_Long || entry.type == ITEM_Double)
		{
			if (result->params_cnt >= DESCRIPTOR_MAX_PARAMS)
				return -1;

			result->params[result->params_cnt].type      = ITEM_Top;
			result->params[result->params_cnt].cpool_idx = 0;
			result->params[result->params_cnt].offset    = 0;
			result->params_cnt++;
		}
	}

	/* Skip over ') */
	pos++;

	/* Parse return type */
	if (descriptor[pos] == 'V')
	{
		result->is_void          = 1;
		result->return_type.type = ITEM_Top;
	}
	else
	{
		result->is_void = 0;
		if (parse_single_type(cf, descriptor, &pos, &result->return_type) != 0)
			return -1;
	}

	return 0;
}

int
parse_field_descriptor(const class_file_t *cf,
                       const char *descriptor,
                       verification_type_entry_t *result)
{
	assert(cf != NULL);
	assert(descriptor != NULL);
	assert(result != NULL);

	if (!cf || !descriptor || !result)
		return -1;

	int pos = 0;
	return parse_single_type(cf, descriptor, &pos, result);
}

/*
 * Chase a Methodref/InterfaceMethodref -> NameAndType -> descriptor UTF-8.
 */
const char *
get_methodref_descriptor(const class_file_t *cf, u2 methodref_idx)
{
	if (methodref_idx == 0 || methodref_idx >= cf->constant_pool_count)
		return NULL;

	const constant_pool_info_t *cp_entry = &cf->constant_pool[methodref_idx];

	/* Accept both Methodref and InterfaceMethodRef */
	u2 nat_idx;
	if (cp_entry->tag == CONSTANT_Methodref)
		nat_idx = cp_entry->info.methodref.name_and_type_index;
	else if (cp_entry->tag == CONSTANT_InterfaceMethodref)
		nat_idx = cp_entry->info.interfaceref.name_and_type_index;
	else
		return NULL;

	if (nat_idx == 0 || nat_idx >= cf->constant_pool_count)
		return NULL;

	const constant_pool_info_t *nat = &cf->constant_pool[nat_idx];
	if (nat->tag != CONSTANT_NameAndType)
		return NULL;

	u2 desc_idx = nat->info.name_and_type.descriptor_index;
	return bytecode_get_utf8_constant(cf, desc_idx);
}

/*
 * Chase a Fieldref -> NameAndType -> descriptor UTF-8.
 */
const char *
get_fieldref_descriptor(const class_file_t *cf, u2 fieldref_idx)
{
	if (fieldref_idx == 0 || fieldref_idx >= cf->constant_pool_count)
		return NULL;

	const constant_pool_info_t *entry = &cf->constant_pool[fieldref_idx];
	if (entry->tag != CONSTANT_Fieldref)
		return NULL;

	u2 nat_index = entry->info.fieldref.name_and_type_index;
	if (nat_index == 0 || nat_index >= cf->constant_pool_count)
		return NULL;

	const constant_pool_info_t *nat = &cf->constant_pool[nat_index];
	if (nat->tag != CONSTANT_NameAndType)
		return NULL;

	u2 desc_index = nat->info.name_and_type.descriptor_index;
	return bytecode_get_utf8_constant(cf, desc_index);
}

/*
 * Given a Methodref/Fieldref/InterfaceMethodref index, return the
 * class_index (a CONSTANT_Class cpool index) for use with ITEM_Object.
 */
u2
get_ref_class_index(const class_file_t *cf, u2 ref_idx)
{
	if (ref_idx == 0 || ref_idx >= cf->constant_pool_count)
		return 0;

	const constant_pool_info_t *entry = &cf->constant_pool[ref_idx];
	switch (entry->tag)
	{
		case CONSTANT_Methodref:
			return entry->info.methodref.class_index;
		case CONSTANT_Fieldref:
			return entry->info.fieldref.class_index;
		case CONSTANT_InterfaceMethodref:
			return entry->info.interfaceref.class_index;
		default:
			return 0;
	}
}
