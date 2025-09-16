/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_CLASS_H
#define JVM_CLASS_H

#include <stdint.h>

typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;

#define CLASS_FILE_MAGIC            0xCAFEBABE

#define CONSTANT_Utf8               1
#define CONSTANT_Integer            3
#define CONSTANT_Float              4
#define CONSTANT_Long               5
#define CONSTANT_Double             6
#define CONSTANT_Class              7
#define CONSTANT_String             8
#define CONSTANT_Fieldref           9
#define CONSTANT_Methodref          10
#define CONSTANT_InterfaceMethodref 11
#define CONSTANT_NameAndType        12
#define CONSTANT_MethodHandle       15
#define CONSTANT_MethodType         16
#define CONSTANT_InvokeDynamic      18

typedef struct cp_info cp_info_t;
typedef struct method_info method_info_t;
typedef struct attr_info attr_info_t;
typedef struct field_info field_info_t;
typedef struct class_file class_file_t;

/* Constant pool */
struct cp_info
{
	u1 tag;
	union {
		struct
		{
			u2 length;
			const u1 *bytes;
		} utf8;
		struct
		{
			u2 class_index;
			u2 name_and_type_index;
		} methodref;
		struct
		{
			u2 class_index;
			u2 name_and_type_index;
		} fieldref;
		struct
		{
			u2 class_index;
			u2 name_and_type_index;
		} interfaceref;
		struct
		{
			u2 name_index;
			u2 descriptor_index;
		} name_and_type;
		struct
		{
			u2 name_index;
		} class_info;
		u4 integer;

	} info;
};

struct attr_info
{
	u2 attribute_name_index;
	u4 attribute_length;
	u1 *info;
};
struct method_info
{
	u2 access_flags;
	u2 name_index;
	u2 descriptor_index;
	u2 attributes_count;
	attr_info_t *attributes;
};

struct field_info
{
	u2 access_flags;
	u2 name_index;
	u2 descriptor_index;
	u2 attributes_count;
	attr_info_t *attributes;
};

/* Class file representation
https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html
ClassFile {
    u4             magic;
    u2             minor_version;
    u2             major_version;
    u2             constant_pool_count;
    cp_info        constant_pool[constant_pool_count-1];
    u2             access_flags;
    u2             this_class;
    u2             super_class;
    u2             interfaces_count;
    u2             interfaces[interfaces_count];
    u2             fields_count;
    field_info     fields[fields_count];
    u2             methods_count;
    method_info    methods[methods_count];
    u2             attributes_count;
    attribute_info attributes[attributes_count];
}
*/
struct class_file
{
	u4 magic;
	u2 minor_version;
	u2 major_version;
	u2 constant_pool_count;
	cp_info_t *constant_pool;
	u2 access_flags;
	u2 this_class;
	u2 super_class;
	u2 interfaces_count;
	u2 *interfaces;
	u2 fields_count;
	field_info_t *fields;
	u2 methods_count;
	method_info_t *methods;
	u2 attributes_count;
	attr_info_t *attributes;
};

u2 read_u2_and_advance(const u1 *data, int *offset);

u4 read_u4_and_advance(const u1 *data, int *offset);

void write_u2_and_advance(u1 *data, int *offset, u2 value);

void write_u4_and_advance(u1 *data, int *offset, u4 value);

#endif /* JVM_CLASS_H */