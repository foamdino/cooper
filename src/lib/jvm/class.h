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
typedef int16_t i2;
typedef int32_t i4;

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
#define CONSTANT_Dynamic            17
#define CONSTANT_InvokeDynamic      18
#define CONSTANT_Module             19
#define CONSTANT_Package            20

/* These are the num bytes for
the fixed size (not including the variable array)
*/
#define ATTR_INFO_HDR_SZ   6
#define METHOD_INFO_HDR_SZ 8
#define FIELD_INFO_HDR_SZ  8

typedef struct constant_pool_info constant_pool_info_t;
typedef struct method_info method_info_t;
typedef struct attr_info attr_info_t;
typedef struct field_info field_info_t;
typedef struct class_file class_file_t;
typedef struct code_info code_info_t;

/* Constant pool info entry */
struct constant_pool_info
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
		u2 string; /* Pointer to utf8 */
		u4 integer;
		u4 float_info; /* float is C */

		struct
		{
			u4 high_bytes;
			u4 low_bytes;
		} long_info;

		struct
		{
			u4 high_bytes;
			u4 low_bytes;
		} double_info;

		struct
		{
			u1 reference_kind;
			u2 reference_index;
		} methodhandle_info;

		struct
		{
			u2 descriptor_index;
		} methodtype_info;

		struct
		{
			u2 bootstrap_method_attr_index;
			u2 name_and_type_index;
		} dynamic_info;
		struct
		{
			u2 bootstrap_method_attr_index;
			u2 name_and_type_index;
		} invokedynamic_info;
		struct
		{
			u2 name_index;
		} module_info;
		struct
		{
			u2 name_index;
		} package_info;

	} info;
};

struct attr_info
{
	u2 attribute_name_index;
	u4 attribute_length;
	const u1 *info;
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

/* Code info
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
struct code_info
{
	u2 max_stack;
	u2 max_locals;
	u4 code_length;
	const u1 *bytecode;
	u2 exception_table_length;
	const u1 *exception_table_data;
	u2 attributes_count;
	const u1 *attributes_data;
};

/* Class file representation
https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.4
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
	constant_pool_info_t *constant_pool;
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

u1 read_u1_and_advance(const u1 *data, int *offset);

u2 read_u2_and_advance(const u1 *data, int *offset);

u4 read_u4_and_advance(const u1 *data, int *offset);

u2 read_u2(const u1 *data);

u4 read_u4(const u1 *data);

void write_u1_and_advance(u1 *data, int *offset, u1 value);

void write_u2_and_advance(u1 *data, int *offset, u2 value);

void write_u4_and_advance(u1 *data, int *offset, u4 value);

void write_i4(u1 *dest, i4 value);

#endif /* JVM_CLASS_H */