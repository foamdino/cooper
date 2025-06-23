/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef AGENT_H
#define AGENT_H

#include <jni.h>
#include <jvmti.h>

/* Forward declaration */
typedef struct agent_context agent_context_t;

/**
 * Header for jvm agent functions
 */

/* JVM agent entry point - called by JVM on agent load */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved); 

#endif /* AGENT_H */