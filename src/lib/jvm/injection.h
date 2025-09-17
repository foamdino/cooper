/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_INJECTION_H
#define JVM_INJECTION_H

#include "bytecode.h"
#include "../arena.h"

typedef struct injection_config injection_config_t;

struct injection_config
{
	const char *callback_class; /**< eg. "com/myagent/MethodTracker" */
	const char *entry_method;   /**< eg. "onMethodEntry" */
	const char *exit_method;    /**< eg. "onMethodExit" */
	const char
	    *entry_sig; /**< eg.
	                   "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V" */
	const char
	    *exit_sig; /**< eg.
	                  "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V" */
};

bytecode_result_e injection_add_method_tracking(arena_t *arena,
                                                class_file_t *cf,
                                                injection_config_t *config);

/* Helper function to find or create constant pool entries */
u2 injection_find_or_add_utf8_constant(arena_t *arena, class_file_t *cf, const char *str);
u2 injection_find_or_add_class_constant(arena_t *arena,
                                        class_file_t *cf,
                                        const char *class_name);
u2 injection_find_or_add_methodref_constant(arena_t *arena,
                                            class_file_t *cf,
                                            const char *class_name,
                                            const char *method_name,
                                            const char *method_sig);

#endif /* JVM_INJECTION_H */