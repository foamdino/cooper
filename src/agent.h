/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef AGENT_H
#define AGENT_H

#include <jni.h>
#include <jvmti.h>
#include "cooper.h"

/* Agent entry point and JVMTI setup */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved);
int init_jvm_capabilities(agent_context_t *ctx);

/* JVMTI callback functions */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method);
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, 
                                 jboolean was_popped_by_exception, jvalue return_value);
void JNICALL exception_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jmethodID method, 
                               jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location);
void JNICALL vm_init_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread);
void JNICALL thread_end_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread);
void JNICALL object_alloc_callback(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread, 
                                  jobject object, jclass object_klass, jlong size);

#endif /* AGENT_H */