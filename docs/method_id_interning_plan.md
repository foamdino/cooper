# Method ID Interning Implementation Plan

## Overview

Replace string-based method event recording with numeric method IDs to eliminate string handling from the hot path. Method metadata is registered once during bytecode injection and referenced by ID thereafter.

## Current Flow (Slow)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Instrumented Method Called                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Injected Bytecode:                                                      │
│   ldc "com/example/Foo"                                                 │
│   ldc "doWork"                                                          │
│   ldc "()V"                                                             │
│   invokestatic NativeTracker.onMethodEntry(String,String,String)V       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ JNI Callback:                                                           │
│   1. GetStringUTFChars x3 (allocation + copy)                           │
│   2. Build class signature key                                          │
│   3. Hash table lookup for class info                                   │
│   4. strlen x3                                                          │
│   5. memcpy strings into ring buffer                                    │
│   6. ReleaseStringUTFChars x3                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

## Proposed Flow (Fast)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Class Loading (One-time setup)                                          │
│   - Register method in registry                                         │
│   - Get method_id (uint32_t)                                            │
│   - Inject constant into bytecode                                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Instrumented Method Called                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Injected Bytecode:                                                      │
│   ldc #42                        /* constant pool integer */            │
│   invokestatic NativeTracker.onMethodEntry(I)V                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ JNI Callback:                                                           │
│   1. Write fixed-size struct to ring buffer                             │
│   (No strings, no allocations, no lookups)                              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Method Registry Data Structure

**File:** `src/agent/method_registry.h`

```c
#ifndef COOPER_METHOD_REGISTRY_H
#define COOPER_METHOD_REGISTRY_H

#include <stdint.h>
#include <stddef.h>
#include "arena.h"

#define MAX_METHODS           65536  /* 64K methods should suffice */
#define INVALID_METHOD_ID     0      /* Reserve 0 as invalid */

typedef struct
{
    /* Struct-of-arrays for cache efficiency during export */
    char    **class_names;      /* Arena-allocated strings */
    char    **method_names;
    char    **method_sigs;
    uint32_t *class_name_lens;  /* Pre-computed for fast serialization */
    uint32_t *method_name_lens;
    uint32_t *method_sig_lens;
    
    uint32_t  count;            /* Next ID to assign (1-indexed) */
    uint32_t  capacity;
    
    pthread_mutex_t lock;       /* Protects registration (not lookup) */
} method_registry_t;

/* Initialize registry with given capacity */
int method_registry_init(method_registry_t *registry, 
                         arena_t *arena, 
                         uint32_t capacity);

/* Register a method, returns method_id (1-indexed) or 0 on failure */
uint32_t method_registry_add(method_registry_t *registry,
                             arena_t *arena,
                             const char *class_name,
                             const char *method_name,
                             const char *method_sig);

/* Lookup method info by ID (lock-free, safe for hot path) */
static inline const char *
method_registry_get_class(const method_registry_t *registry, uint32_t id)
{
    if (id == 0 || id > registry->count)
        return NULL;
    return registry->class_names[id - 1];
}

/* Similar getters for method_name, method_sig */

#endif /* COOPER_METHOD_REGISTRY_H */
```

**Design decisions:**

- **1-indexed IDs:** Reserve 0 as invalid/sentinel value
- **Struct-of-arrays:** Better cache locality when iterating for export
- **Pre-computed lengths:** Avoid strlen during serialization
- **Lock only on write:** Reads are lock-free (append-only structure)
- **Arena allocation:** Strings never freed individually

### 2. Method Registry Implementation

**File:** `src/agent/method_registry.c`

```c
#include "method_registry.h"
#include "log.h"
#include <string.h>
#include <assert.h>

int
method_registry_init(method_registry_t *registry, 
                     arena_t *arena, 
                     uint32_t capacity)
{
    assert(registry != NULL);
    assert(arena != NULL);
    
    if (capacity == 0 || capacity > MAX_METHODS)
        capacity = MAX_METHODS;
    
    registry->class_names = arena_alloc(arena, capacity * sizeof(char *));
    registry->method_names = arena_alloc(arena, capacity * sizeof(char *));
    registry->method_sigs = arena_alloc(arena, capacity * sizeof(char *));
    registry->class_name_lens = arena_alloc(arena, capacity * sizeof(uint32_t));
    registry->method_name_lens = arena_alloc(arena, capacity * sizeof(uint32_t));
    registry->method_sig_lens = arena_alloc(arena, capacity * sizeof(uint32_t));
    
    if (!registry->class_names || !registry->method_names || 
        !registry->method_sigs || !registry->class_name_lens ||
        !registry->method_name_lens || !registry->method_sig_lens)
    {
        LOG_ERROR("Failed to allocate method registry arrays");
        return COOPER_ERR;
    }
    
    registry->count = 0;
    registry->capacity = capacity;
    
    if (pthread_mutex_init(&registry->lock, NULL) != 0)
    {
        LOG_ERROR("Failed to initialize method registry mutex");
        return COOPER_ERR;
    }
    
    return COOPER_OK;
}

uint32_t
method_registry_add(method_registry_t *registry,
                    arena_t *arena,
                    const char *class_name,
                    const char *method_name,
                    const char *method_sig)
{
    assert(registry != NULL);
    assert(class_name != NULL);
    assert(method_name != NULL);
    assert(method_sig != NULL);
    
    pthread_mutex_lock(&registry->lock);
    
    if (registry->count >= registry->capacity)
    {
        LOG_WARN("Method registry full (%u methods)", registry->capacity);
        pthread_mutex_unlock(&registry->lock);
        return INVALID_METHOD_ID;
    }
    
    uint32_t idx = registry->count;
    
    /* Duplicate strings into arena */
    registry->class_names[idx] = arena_strdup(arena, class_name);
    registry->method_names[idx] = arena_strdup(arena, method_name);
    registry->method_sigs[idx] = arena_strdup(arena, method_sig);
    
    if (!registry->class_names[idx] || !registry->method_names[idx] ||
        !registry->method_sigs[idx])
    {
        LOG_ERROR("Failed to allocate method strings");
        pthread_mutex_unlock(&registry->lock);
        return INVALID_METHOD_ID;
    }
    
    /* Pre-compute lengths */
    registry->class_name_lens[idx] = (uint32_t)strlen(class_name);
    registry->method_name_lens[idx] = (uint32_t)strlen(method_name);
    registry->method_sig_lens[idx] = (uint32_t)strlen(method_sig);
    
    registry->count++;
    
    /* Return 1-indexed ID */
    uint32_t method_id = idx + 1;
    
    pthread_mutex_unlock(&registry->lock);
    
    LOG_DEBUG("Registered method ID %u: %s.%s%s", 
              method_id, class_name, method_name, method_sig);
    
    return method_id;
}
```

### 3. Compact Method Event Structure

**File:** `src/common/protocol.h` (or appropriate header)

```c
/* 
 * Compact method event - fixed size, no strings
 * Total: 32 bytes (fits in half a cache line)
 */
typedef struct __attribute__((packed))
{
    uint64_t timestamp;     /* Nanoseconds since epoch */
    uint64_t cpu_cycles;    /* RDTSC value */
    uint32_t method_id;     /* Index into method registry */
    uint32_t thread_id;     /* OS thread ID */
    uint8_t  event_type;    /* METHOD_ENTRY or METHOD_EXIT */
    uint8_t  padding[7];    /* Align to 32 bytes */
} compact_method_event_t;

_Static_assert(sizeof(compact_method_event_t) == 32, 
               "compact_method_event_t must be 32 bytes");
```

### 4. Updated NativeTracker Java Class

**File:** `src/java/com/github/foamdino/cooper/agent/NativeTracker.java`

```java
package com.github.foamdino.cooper.agent;

public final class NativeTracker {
    
    /* New simplified entry points */
    public static native void onMethodEntry(int methodId);
    public static native void onMethodExit(int methodId);
    
    /* 
     * Legacy entry points - keep for backwards compatibility during migration
     * Mark as @Deprecated to track usage
     */
    @Deprecated
    public static native void onMethodEntry(String className, 
                                            String methodName, 
                                            String methodSignature);
    @Deprecated
    public static native void onMethodExit(String className, 
                                           String methodName, 
                                           String methodSignature);
    
    private NativeTracker() {} /* Prevent instantiation */
}
```

### 5. Updated JNI Callbacks

**File:** `src/agent/cooper.c`

```c
/*
 * Fast path method entry - no string handling
 */
JNIEXPORT void JNICALL
Java_com_github_foamdino_cooper_agent_NativeTracker_onMethodEntry__I(
    JNIEnv *env,
    jclass klass,
    jint methodId)
{
    UNUSED(env);
    UNUSED(klass);
    
    if (methodId <= 0)
        return;
    
    uint32_t handle;
    if (mpsc_ring_reserve(&global_ctx->compact_method_ring, &handle) != 0)
        return; /* Ring full - drop event silently */
    
    compact_method_event_t *event = 
        mpsc_ring_get(&global_ctx->compact_method_ring, handle);
    
    event->method_id  = (uint32_t)methodId;
    event->event_type = METHOD_ENTRY;
    event->timestamp  = get_current_time_ns();
    event->thread_id  = get_current_thread_id();
    event->cpu_cycles = cycles_start();
    
    mpsc_ring_commit(&global_ctx->compact_method_ring, handle);
}

JNIEXPORT void JNICALL
Java_com_github_foamdino_cooper_agent_NativeTracker_onMethodExit__I(
    JNIEnv *env,
    jclass klass,
    jint methodId)
{
    UNUSED(env);
    UNUSED(klass);
    
    if (methodId <= 0)
        return;
    
    uint32_t handle;
    if (mpsc_ring_reserve(&global_ctx->compact_method_ring, &handle) != 0)
        return;
    
    compact_method_event_t *event = 
        mpsc_ring_get(&global_ctx->compact_method_ring, handle);
    
    event->method_id  = (uint32_t)methodId;
    event->event_type = METHOD_EXIT;
    event->timestamp  = get_current_time_ns();
    event->thread_id  = get_current_thread_id();
    event->cpu_cycles = cycles_end();
    
    mpsc_ring_commit(&global_ctx->compact_method_ring, handle);
}
```

**Note:** The `__I` suffix in the function name is JNI name mangling for `(I)V` signature (takes int, returns void).

### 6. Bytecode Injection Changes

**Current injection (strings):**

```
ldc           #X    // String "com/example/Foo"
ldc           #Y    // String "doWork"  
ldc           #Z    // String "()V"
invokestatic  #W    // NativeTracker.onMethodEntry(LString;LString;LString;)V
```

**New injection (integer ID):**

```
ldc           #X    // Integer 42 (method ID)
invokestatic  #Y    // NativeTracker.onMethodEntry(I)V
```

#### 6.1 Constant Pool Changes

Need to add to constant pool during instrumentation:

1. `CONSTANT_Integer` entry for the method ID
2. `CONSTANT_Methodref` for `NativeTracker.onMethodEntry(I)V`

**Modification to bytecode builder:**

```c
/*
 * Add integer constant to constant pool
 * Returns constant pool index or 0 on failure
 */
uint16_t
cp_add_integer(classfile_builder_t *builder, int32_t value)
{
    if (builder->cp_count >= MAX_CP_ENTRIES)
        return 0;
    
    uint16_t idx = builder->cp_count;
    
    /* CONSTANT_Integer_info structure */
    builder->cp_tags[idx] = CONSTANT_Integer;
    builder->cp_data[idx].integer_value = value;
    builder->cp_count++;
    
    return idx + 1; /* CP indices are 1-based */
}

/*
 * Build method entry injection bytecode with integer ID
 */
int
build_method_entry_injection_int(bytecode_builder_t *bb, 
                                 uint16_t method_id_cp_idx,
                                 uint16_t tracker_method_cp_idx)
{
    /* ldc #method_id_cp_idx */
    if (method_id_cp_idx <= 255)
    {
        bytecode_emit_u8(bb, 0x12);  /* ldc */
        bytecode_emit_u8(bb, (uint8_t)method_id_cp_idx);
    }
    else
    {
        bytecode_emit_u8(bb, 0x13);  /* ldc_w */
        bytecode_emit_u16(bb, method_id_cp_idx);
    }
    
    /* invokestatic NativeTracker.onMethodEntry(I)V */
    bytecode_emit_u8(bb, 0xB8);  /* invokestatic */
    bytecode_emit_u16(bb, tracker_method_cp_idx);
    
    return COOPER_OK;
}
```

#### 6.2 Integration with ClassFileLoadHook

```c
static void JNICALL
cb_class_file_load_hook(jvmtiEnv *jvmti,
                        JNIEnv *jni,
                        jclass class_being_redefined,
                        jobject loader,
                        const char *name,
                        jobject protection_domain,
                        jint class_data_len,
                        const unsigned char *class_data,
                        jint *new_class_data_len,
                        unsigned char **new_class_data)
{
    /* ... existing filter checks ... */
    
    /* Parse class file */
    classfile_t cf;
    if (parse_classfile(class_data, class_data_len, &cf) != COOPER_OK)
        return;
    
    /* For each method to instrument */
    for (uint16_t i = 0; i < cf.methods_count; i++)
    {
        method_info_t *method = &cf.methods[i];
        
        if (!should_instrument_method(name, method->name, method->descriptor))
            continue;
        
        /* Register method and get ID */
        uint32_t method_id = method_registry_add(
            &global_ctx->method_registry,
            global_ctx->arenas[BYTECODE_ARENA_ID],
            name,
            method->name,
            method->descriptor);
        
        if (method_id == INVALID_METHOD_ID)
        {
            LOG_WARN("Failed to register method %s.%s", name, method->name);
            continue;
        }
        
        /* Inject with integer ID instead of strings */
        inject_method_entry_int(&cf, method, method_id);
    }
    
    /* ... serialize modified class ... */
}
```

### 7. Shared Memory Export for Consumer

The CLI/TUI consumer needs access to the method registry to resolve IDs to names.

#### 7.1 Shared Memory Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Shared Memory Layout                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│ Header (64 bytes)                                                       │
│   - magic: uint32_t                                                     │
│   - version: uint32_t                                                   │
│   - method_count: uint32_t                                              │
│   - method_table_offset: uint32_t                                       │
│   - string_pool_offset: uint32_t                                        │
│   - ... padding ...                                                     │
├─────────────────────────────────────────────────────────────────────────┤
│ Method Table (method_count * sizeof(shm_method_entry_t))                │
│   For each method:                                                      │
│     - class_name_offset: uint32_t  (offset into string pool)            │
│     - method_name_offset: uint32_t                                      │
│     - method_sig_offset: uint32_t                                       │
│     - class_name_len: uint16_t                                          │
│     - method_name_len: uint16_t                                         │
│     - method_sig_len: uint16_t                                          │
│     - padding: uint16_t                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ String Pool                                                             │
│   - Packed null-terminated strings                                      │
│   - Referenced by offsets in method table                               │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 7.2 Export Structures

```c
#define SHM_METHOD_REGISTRY_MAGIC 0x4D544852  /* "MTHR" */
#define SHM_METHOD_REGISTRY_VERSION 1

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint32_t version;
    uint32_t method_count;
    uint32_t method_table_offset;
    uint32_t string_pool_offset;
    uint32_t string_pool_size;
    uint8_t  reserved[40];  /* Pad to 64 bytes */
} shm_method_registry_header_t;

_Static_assert(sizeof(shm_method_registry_header_t) == 64,
               "Header must be 64 bytes");

typedef struct __attribute__((packed))
{
    uint32_t class_name_offset;
    uint32_t method_name_offset;
    uint32_t method_sig_offset;
    uint16_t class_name_len;
    uint16_t method_name_len;
    uint16_t method_sig_len;
    uint16_t padding;
} shm_method_entry_t;

_Static_assert(sizeof(shm_method_entry_t) == 20,
               "Method entry must be 20 bytes");
```

#### 7.3 Export Function

```c
int
method_registry_export_shm(const method_registry_t *registry,
                           void *shm_base,
                           size_t shm_size)
{
    /* Calculate required size */
    size_t header_size = sizeof(shm_method_registry_header_t);
    size_t table_size = registry->count * sizeof(shm_method_entry_t);
    
    size_t string_pool_size = 0;
    for (uint32_t i = 0; i < registry->count; i++)
    {
        string_pool_size += registry->class_name_lens[i] + 1;
        string_pool_size += registry->method_name_lens[i] + 1;
        string_pool_size += registry->method_sig_lens[i] + 1;
    }
    
    size_t total_size = header_size + table_size + string_pool_size;
    if (total_size > shm_size)
    {
        LOG_ERROR("Shared memory too small: need %zu, have %zu",
                  total_size, shm_size);
        return COOPER_ERR;
    }
    
    /* Write header */
    shm_method_registry_header_t *header = shm_base;
    header->magic = SHM_METHOD_REGISTRY_MAGIC;
    header->version = SHM_METHOD_REGISTRY_VERSION;
    header->method_count = registry->count;
    header->method_table_offset = header_size;
    header->string_pool_offset = header_size + table_size;
    header->string_pool_size = string_pool_size;
    
    /* Write method table and string pool */
    shm_method_entry_t *table = 
        (shm_method_entry_t *)((char *)shm_base + header->method_table_offset);
    char *string_pool = (char *)shm_base + header->string_pool_offset;
    uint32_t string_offset = 0;
    
    for (uint32_t i = 0; i < registry->count; i++)
    {
        /* Class name */
        table[i].class_name_offset = string_offset;
        table[i].class_name_len = registry->class_name_lens[i];
        memcpy(string_pool + string_offset, 
               registry->class_names[i], 
               registry->class_name_lens[i] + 1);
        string_offset += registry->class_name_lens[i] + 1;
        
        /* Method name */
        table[i].method_name_offset = string_offset;
        table[i].method_name_len = registry->method_name_lens[i];
        memcpy(string_pool + string_offset,
               registry->method_names[i],
               registry->method_name_lens[i] + 1);
        string_offset += registry->method_name_lens[i] + 1;
        
        /* Method signature */
        table[i].method_sig_offset = string_offset;
        table[i].method_sig_len = registry->method_sig_lens[i];
        memcpy(string_pool + string_offset,
               registry->method_sigs[i],
               registry->method_sig_lens[i] + 1);
        string_offset += registry->method_sig_lens[i] + 1;
    }
    
    return COOPER_OK;
}
```

### 8. Consumer-Side Method Resolution

**File:** `src/cli/method_registry_reader.c`

```c
typedef struct
{
    const shm_method_registry_header_t *header;
    const shm_method_entry_t *table;
    const char *string_pool;
} method_registry_reader_t;

int
method_registry_reader_init(method_registry_reader_t *reader, 
                            const void *shm_base)
{
    const shm_method_registry_header_t *header = shm_base;
    
    if (header->magic != SHM_METHOD_REGISTRY_MAGIC)
    {
        fprintf(stderr, "Invalid method registry magic\n");
        return -1;
    }
    
    if (header->version != SHM_METHOD_REGISTRY_VERSION)
    {
        fprintf(stderr, "Unsupported method registry version: %u\n",
                header->version);
        return -1;
    }
    
    reader->header = header;
    reader->table = (const shm_method_entry_t *)
        ((const char *)shm_base + header->method_table_offset);
    reader->string_pool = (const char *)shm_base + header->string_pool_offset;
    
    return 0;
}

/* 
 * Get method info by ID (1-indexed)
 * Returns pointers directly into shared memory - do not free
 */
int
method_registry_reader_get(const method_registry_reader_t *reader,
                           uint32_t method_id,
                           const char **class_name,
                           const char **method_name,
                           const char **method_sig)
{
    if (method_id == 0 || method_id > reader->header->method_count)
        return -1;
    
    uint32_t idx = method_id - 1;
    const shm_method_entry_t *entry = &reader->table[idx];
    
    *class_name = reader->string_pool + entry->class_name_offset;
    *method_name = reader->string_pool + entry->method_name_offset;
    *method_sig = reader->string_pool + entry->method_sig_offset;
    
    return 0;
}
```

## Implementation Order

### Phase 1: Foundation (4-6 hours)

1. [ ] Create `method_registry.h` and `method_registry.c`
2. [ ] Add unit tests for registry operations
3. [ ] Integrate registry initialization into agent startup
4. [ ] Add registry to `global_ctx` structure

### Phase 2: Compact Events (2-3 hours)

1. [ ] Define `compact_method_event_t` structure
2. [ ] Create separate ring buffer for compact events
3. [ ] Implement new JNI callbacks (`onMethodEntry(I)V`, `onMethodExit(I)V`)
4. [ ] Update `NativeTracker.java` with new native method declarations

### Phase 3: Bytecode Injection (6-8 hours)

1. [ ] Add `cp_add_integer()` to constant pool builder
2. [ ] Create `build_method_entry_injection_int()` function
3. [ ] Modify `ClassFileLoadHook` to:
    - Register method in registry
    - Use integer injection instead of string injection
4. [ ] Update StackMapTable generation for new bytecode sequence
5. [ ] Test with simple classes, then complex Spring Boot apps

### Phase 4: Shared Memory Export (3-4 hours)

1. [ ] Define shared memory layout structures
2. [ ] Implement `method_registry_export_shm()`
3. [ ] Add periodic/triggered export in background thread
4. [ ] Handle incremental updates (new methods registered after initial export)

### Phase 5: Consumer Updates (3-4 hours)

1. [ ] Implement `method_registry_reader_t` in CLI/TUI
2. [ ] Update event processing to resolve method IDs
3. [ ] Add caching layer for frequently accessed methods
4. [ ] Update display formatting

### Phase 6: Migration & Cleanup (2-3 hours)

1. [ ] Add feature flag to switch between old/new injection
2. [ ] Benchmark comparison (old vs new)
3. [ ] Remove legacy string-based code paths
4. [ ] Update documentation

## Testing Strategy

### Unit Tests

- Registry add/lookup with boundary conditions
- Constant pool integer addition
- Bytecode sequence generation
- Shared memory serialization/deserialization

### Integration Tests

- Instrument simple class, verify method ID in events
- Instrument class with many methods, verify all IDs unique
- Consumer correctly resolves all method IDs
- Hot-reload scenario: new classes added after startup

### Performance Tests

- Measure callback overhead: old vs new
- Measure events/second throughput
- Measure ring buffer utilization
- Memory footprint comparison

## Rollback Plan

Keep legacy code paths behind feature flag:

```c
if (global_ctx->config.use_method_id_interning)
{
    /* New path: integer ID */
    inject_method_entry_int(&cf, method, method_id);
}
else
{
    /* Legacy path: strings */
    inject_method_entry_strings(&cf, method);
}
```

## Open Questions

1. **Maximum method count:** Is 64K methods sufficient? Large enterprise apps might have more. Consider dynamic growth or configurable limit.

2. **Method deduplication:** If the same method is loaded by multiple classloaders, should they share an ID or have separate IDs? (Separate is simpler, shared saves space)

3. **Late binding:** What happens if consumer starts before agent has registered methods? Need to handle empty/partial registry gracefully.

4. **Incremental export:** Should shared memory be updated atomically or is eventual consistency acceptable? (Atomic requires double-buffering or versioning)

5. **ID stability across restarts:** Should method IDs be deterministic (hash-based) for easier cross-session analysis, or is sequential assignment sufficient?

## Estimated Total Effort

| Phase | Hours |
|-------|-------|
| Phase 1: Foundation | 4-6 |
| Phase 2: Compact Events | 2-3 |
| Phase 3: Bytecode Injection | 6-8 |
| Phase 4: Shared Memory Export | 3-4 |
| Phase 5: Consumer Updates | 3-4 |
| Phase 6: Migration & Cleanup | 2-3 |
| **Total** | **20-28 hours** |

## References

- JNI Specification: Name mangling for overloaded methods
- JVMTI ClassFileLoadHook documentation
- async-profiler source: Similar method interning approach
