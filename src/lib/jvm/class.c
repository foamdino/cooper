/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "class.h"

/*
A set of functions to read data from a class file:

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

/* Read big endian 16bit value */
u2
read_u2(const u1 *data, int *offset)
{
	u2 v = (data[*offset] << 8) | data[*offset + 1];
	*offset += 2;
	return v;
}

/* Read big endian 32bit value */
u4
read_u4(const u1 *data, int *offset)
{
	u4 v = (data[*offset] << 24) | (data[*offset + 1] << 16)
	       | (data[*offset + 2] << 8) | data[*offset + 3];
	*offset += 4;
	return v;
}