/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <sys/stat.h>

#include "../lib/jvm/bytecode.h"

/* Read entire file into buffer */
static u1 *
read_file(const char *filename, u4 *size)
{
	FILE *file = fopen(filename, "rb");
	if (!file)
	{
		printf("Failed to open file: %s\n", filename);
		return NULL;
	}

	struct stat st;
	if (stat(filename, &st) != 0)
	{
		fclose(file);
		return NULL;
	}

	*size      = st.st_size;
	u1 *buffer = malloc(*size);
	if (!buffer)
	{
		fclose(file);
		return NULL;
	}

	if (fread(buffer, 1, *size, file) != *size)
	{
		free(buffer);
		fclose(file);
		return NULL;
	}

	fclose(file);
	return buffer;
}

int
main()
{
	u4 class_size;
	u1 *class_data = read_file("com/github/foamdino/Test.class", &class_size);

	if (!class_data)
		return -1;

	arena_t *class_arena = arena_init("class-arena", 1024 * 1024, 1024);
	if (!class_arena)
	{
		free(class_data);
		return -1;
	}

	class_file_t *cf = NULL;
	bytecode_result_e res =
	    bytecode_parse_class(class_arena, class_data, class_size, &cf);

	if (res != BYTECODE_SUCCESS)
	{
		printf("Parse failed with %d", res);
		arena_destroy(class_arena);
		free(class_data);
		return -1;
	}

	printf("Parse successful...\n");

	bytecode_print_class_info(cf);

	arena_destroy(class_arena);
	free(class_data);

	return 0;
}