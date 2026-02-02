# StackMapTable Generation Implementation Plan

## Overview

This plan outlines implementing StackMapTable generation for bytecode injection using FULL_FRAME encoding exclusively. Target: ~1500 lines of C code, implementable in phases.

## Goals

- Generate valid StackMapTable for methods after entry/exit injection
- Use only `FULL_FRAME` (type 255) to avoid delta computation complexity
- Support all JVM opcodes with accurate stack/local tracking
- Handle control flow (branches, switches, exception handlers)
- Integrate with existing `bb_add_original_with_exit_injection` workflow

## Phase 1: Extended opcode.def Format

### New Format Definition

```c
/* OPCODE(val, name, len, is_branch, pop_cnt, push_cnt, pop_types, push_types, flags) */

/* Type codes:
 * I = Integer (int, boolean, byte, char, short)
 * J = Long (2 slots)
 * F = Float
 * D = Double (2 slots)
 * R = Reference (object/array)
 * ? = Variable (requires constant pool lookup)
 * = = Copy top of stack (dup operations)
 */

/* Flags (bitmask):
 * 0x01 NEEDS_CP      - Requires constant pool lookup for type
 * 0x02 VARIABLE      - Complex behavior, needs manual handler
 * 0x04 USES_LOCALS   - Reads/writes local variables
 * 0x08 STACK_DUP     - Stack duplication operation
 * 0x10 IS_RETURN     - Method return instruction
 * 0x20 IS_THROW      - Throws exception
 */
```

### Example Entries

```c
#ifdef OPCODE
/* Simple cases - fully automated */
OPCODE(0x00, nop, 1, 0, 0, 0, "", "", 0)
OPCODE(0x01, aconst_null, 1, 0, 0, 1, "", "R", 0)
OPCODE(0x03, iconst_0, 1, 0, 0, 1, "", "I", 0)
OPCODE(0x60, iadd, 1, 0, 2, 1, "II", "I", 0)

/* Requires CP lookup */
OPCODE(0x12, ldc, 2, 0, 0, 1, "", "?", NEEDS_CP)
OPCODE(0x13, ldc_w, 3, 0, 0, 1, "", "?", NEEDS_CP)

/* Complex - needs manual handler */
OPCODE(0xb8, invokestatic, 3, 0, -1, -1, "?", "?", NEEDS_CP|VARIABLE)
OPCODE(0x59, dup, 1, 0, 0, 1, "", "=", STACK_DUP)

/* Returns */
OPCODE(0xac, ireturn, 1, 0, 1, 0, "I", "", IS_RETURN)
OPCODE(0xb1, return, 1, 0, 0, 0, "", "", IS_RETURN)
#endif
```

**Files to modify:**
- `lib/jvm/opcode.def` - extend with new columns
- `lib/jvm/opcode.h` - generate lookup tables

**Estimated effort:** 2-3 hours to update all 200+ opcodes

---

## Phase 2: Core Data Structures

### File: `lib/jvm/stackmap.h`

```c
#ifndef JVM_STACKMAP_H
#define JVM_STACKMAP_H

#include "class.h"
#include "arena.h"

/* Verification types from JVMS §4.10.1.2 */
typedef enum {
    ITEM_Top = 0,
    ITEM_Integer = 1,
    ITEM_Float = 2,
    ITEM_Double = 3,        /* Takes 2 slots */
    ITEM_Long = 4,          /* Takes 2 slots */
    ITEM_Null = 5,
    ITEM_UninitializedThis = 6,
    ITEM_Object = 7,        /* Has cpool_index */
    ITEM_Uninitialized = 8  /* Has offset */
} verification_type_e;

/* Single verification type entry */
typedef struct {
    verification_type_e type;
    u2 cpool_index;  /* For ITEM_Object */
    u2 offset;       /* For ITEM_Uninitialized */
} verification_type_t;

/* Frame state at a specific PC */
typedef struct {
    u4 pc;                           /* Program counter */
    u2 locals_count;
    verification_type_t locals[256];
    u2 stack_count;
    verification_type_t stack[256];
} frame_state_t;

/* Frame computer - tracks state during simulation */
typedef struct {
    arena_t *arena;
    const class_file_t *cf;
    
    frame_state_t current_frame;
    
    /* Branch targets requiring frames */
    u4 *target_pcs;
    u4 target_count;
    u4 target_capacity;
    
    /* Computed frames at targets */
    frame_state_t *frames;
    u4 frame_count;
    u4 frame_capacity;
    
    /* Exception handlers (always need frames) */
    u4 *handler_pcs;
    u4 handler_count;
} frame_computer_t;

/* Public API */
frame_computer_t *fc_create(arena_t *arena, const class_file_t *cf);
int fc_compute_frames(frame_computer_t *fc, 
                     const u1 *bytecode, 
                     u4 bytecode_len,
                     const code_info_t *code_info);
int fc_encode_stackmap_table(frame_computer_t *fc,
                             u1 **output,
                             u4 *output_len);

#endif /* JVM_STACKMAP_H */
```

**Estimated effort:** 1 hour

---

## Phase 3: Instruction Simulation Engine

### File: `lib/jvm/stackmap.c`

#### 3.1 Type Helpers

```c
/* Convert type code to verification type */
static verification_type_e decode_type_code(char code)
{
    switch(code) {
        case 'I': return ITEM_Integer;
        case 'J': return ITEM_Long;
        case 'F': return ITEM_Float;
        case 'D': return ITEM_Double;
        case 'R': return ITEM_Object;
        default:  return ITEM_Top;
    }
}

/* Push type onto stack */
static void push_type(frame_state_t *frame, verification_type_e type, u2 cpool_index)
{
    frame->stack[frame->stack_count].type = type;
    frame->stack[frame->stack_count].cpool_index = cpool_index;
    frame->stack_count++;
    
    /* Long/Double take 2 slots */
    if (type == ITEM_Long || type == ITEM_Double) {
        frame->stack[frame->stack_count].type = ITEM_Top;
        frame->stack_count++;
    }
}

/* Pop type from stack */
static verification_type_e pop_type(frame_state_t *frame)
{
    if (frame->stack_count == 0) return ITEM_Top;
    
    frame->stack_count--;
    verification_type_e type = frame->stack[frame->stack_count].type;
    
    /* Long/Double pop 2 slots */
    if (frame->stack_count > 0 && 
        frame->stack[frame->stack_count - 1].type == ITEM_Long ||
        frame->stack[frame->stack_count - 1].type == ITEM_Double) {
        frame->stack_count--;
    }
    
    return type;
}
```

#### 3.2 Auto-Generated Simulation

```c
/* Generate opcode metadata arrays from opcode.def */
static const int OPCODE_POP_COUNT[256] = {
    #define OPCODE(val, name, len, is_branch, pop_cnt, push_cnt, pop_types, push_types, flags) \
        [val] = pop_cnt,
    #include "opcode.def"
    #undef OPCODE
};

static const int OPCODE_PUSH_COUNT[256] = {
    #define OPCODE(val, name, len, is_branch, pop_cnt, push_cnt, pop_types, push_types, flags) \
        [val] = push_cnt,
    #include "opcode.def"
    #undef OPCODE
};

static const char *OPCODE_PUSH_TYPES[256] = {
    #define OPCODE(val, name, len, is_branch, pop_cnt, push_cnt, pop_types, push_types, flags) \
        [val] = push_types,
    #include "opcode.def"
    #undef OPCODE
};

static const int OPCODE_FLAGS[256] = {
    #define OPCODE(val, name, len, is_branch, pop_cnt, push_cnt, pop_types, push_types, flags) \
        [val] = flags,
    #include "opcode.def"
    #undef OPCODE
};

/* Main simulation dispatcher */
static int simulate_instruction(frame_computer_t *fc,
                                u1 opcode,
                                const u1 *code,
                                u4 pc)
{
    frame_state_t *frame = &fc->current_frame;
    int flags = OPCODE_FLAGS[opcode];
    
    /* Handle special cases first */
    if (flags & VARIABLE) {
        return simulate_variable(fc, opcode, code, pc);
    }
    
    /* Simple case: fixed stack effects */
    int pop_count = OPCODE_POP_COUNT[opcode];
    int push_count = OPCODE_PUSH_COUNT[opcode];
    const char *push_types = OPCODE_PUSH_TYPES[opcode];
    
    /* Pop values */
    for (int i = 0; i < pop_count; i++) {
        pop_type(frame);
    }
    
    /* Push values */
    for (int i = 0; i < push_count; i++) {
        verification_type_e type = decode_type_code(push_types[i]);
        push_type(frame, type, 0);
    }
    
    return 0;
}
```

#### 3.3 Manual Handlers for Complex Instructions

```c
/* Handle VARIABLE instructions requiring CP lookup or descriptor parsing */
static int simulate_variable(frame_computer_t *fc, 
                            u1 opcode,
                            const u1 *code,
                            u4 pc)
{
    switch(opcode) {
        case 0x12: /* ldc */
        case 0x13: /* ldc_w */
            return simulate_ldc(fc, code, pc, opcode == 0x12);
            
        case 0xb6: /* invokevirtual */
        case 0xb7: /* invokespecial */
        case 0xb8: /* invokestatic */
        case 0xb9: /* invokeinterface */
            return simulate_invoke(fc, code, pc, opcode);
            
        case 0x59: /* dup */
        case 0x5a: /* dup_x1 */
        case 0x5b: /* dup_x2 */
            return simulate_dup(fc, opcode);
            
        /* Add more as needed */
    }
    
    return -1;
}

static int simulate_ldc(frame_computer_t *fc, const u1 *code, u4 pc, int is_short)
{
    u2 index = is_short ? code[pc + 1] : read_u2(&code[pc + 1]);
    u1 tag = fc->cf->constant_pool[index].tag;
    
    verification_type_e type;
    u2 cpool_index = 0;
    
    switch(tag) {
        case CONSTANT_Integer:
            type = ITEM_Integer;
            break;
        case CONSTANT_Float:
            type = ITEM_Float;
            break;
        case CONSTANT_String:
        case CONSTANT_Class:
            type = ITEM_Object;
            cpool_index = index;  /* Point to String/Class */
            break;
        default:
            return -1;
    }
    
    push_type(&fc->current_frame, type, cpool_index);
    return 0;
}

static int simulate_invoke(frame_computer_t *fc, const u1 *code, u4 pc, u1 opcode)
{
    u2 methodref_index = read_u2(&code[pc + 1]);
    
    /* Parse method descriptor to get param/return types */
    const char *descriptor = get_methodref_descriptor(fc->cf, methodref_index);
    if (!descriptor) return -1;
    
    /* Pop parameters (parse descriptor) */
    int param_slots = parse_method_params(descriptor);
    for (int i = 0; i < param_slots; i++) {
        pop_type(&fc->current_frame);
    }
    
    /* Pop 'this' for non-static */
    if (opcode != 0xb8) {  /* Not invokestatic */
        pop_type(&fc->current_frame);
    }
    
    /* Push return value if not void */
    char return_type = parse_return_type(descriptor);
    if (return_type != 'V') {
        verification_type_e type = decode_type_code(return_type);
        push_type(&fc->current_frame, type, 0);
    }
    
    return 0;
}
```

**Estimated effort:** 
- Core engine: 4-6 hours
- Manual handlers (20 complex opcodes): 8-10 hours

---

## Phase 4: Control Flow Analysis

### File: `lib/jvm/stackmap.c` (continued)

```c
/* Identify all branch targets requiring frames */
static int identify_branch_targets(frame_computer_t *fc,
                                   const u1 *bytecode,
                                   u4 bytecode_len,
                                   const code_info_t *code_info)
{
    /* Add exception handler targets */
    for (u2 i = 0; i < code_info->exception_table_length; i++) {
        u2 handler_pc = read_u2(&code_info->exception_table_data[i * 8 + 4]);
        add_target(fc, handler_pc);
    }
    
    /* Scan bytecode for branch instructions */
    u4 pc = 0;
    while (pc < bytecode_len) {
        u1 opcode = bytecode[pc];
        
        if (IS_BRANCH[opcode]) {
            u2 offset;
            if (IS_BRANCH[opcode] == 1) {
                offset = read_u2(&bytecode[pc + 1]);
            } else {
                offset = read_u4(&bytecode[pc + 1]);
            }
            
            u4 target = pc + offset;
            add_target(fc, target);
        }
        
        /* Switch instructions */
        if (opcode == 0xaa || opcode == 0xab) {
            /* Parse switch and add all targets */
            parse_switch_targets(fc, bytecode, pc);
        }
        
        pc += get_inst_len(bytecode, pc, bytecode_len);
    }
    
    return 0;
}

static void add_target(frame_computer_t *fc, u4 pc)
{
    /* Check if already present */
    for (u4 i = 0; i < fc->target_count; i++) {
        if (fc->target_pcs[i] == pc) return;
    }
    
    /* Add new target */
    if (fc->target_count >= fc->target_capacity) {
        /* Grow array */
        fc->target_capacity *= 2;
        u4 *new_targets = arena_alloc(fc->arena, 
                                      fc->target_capacity * sizeof(u4));
        memcpy(new_targets, fc->target_pcs, fc->target_count * sizeof(u4));
        fc->target_pcs = new_targets;
    }
    
    fc->target_pcs[fc->target_count++] = pc;
}
```

**Estimated effort:** 3-4 hours

---

## Phase 5: Frame Computation

```c
/* Main computation loop */
int fc_compute_frames(frame_computer_t *fc,
                     const u1 *bytecode,
                     u4 bytecode_len,
                     const code_info_t *code_info)
{
    /* Step 1: Identify all branch targets */
    if (identify_branch_targets(fc, bytecode, bytecode_len, code_info) != 0)
        return -1;
    
    /* Step 2: Initialize frame at PC 0 (method entry) */
    initialize_entry_frame(fc, code_info);
    
    /* Step 3: Simulate execution, recording frames at targets */
    u4 pc = 0;
    while (pc < bytecode_len) {
        u1 opcode = bytecode[pc];
        
        /* Save frame if this is a branch target */
        if (is_target(fc, pc)) {
            save_frame(fc, pc);
        }
        
        /* Simulate instruction */
        if (simulate_instruction(fc, opcode, bytecode, pc) != 0) {
            /* Simulation error - possibly unsupported opcode */
            return -1;
        }
        
        /* Check for control flow changes */
        if (IS_RETURN[opcode] || opcode == 0xbf /* athrow */) {
            /* Execution stops here - don't continue linearly */
            /* Find next unprocessed target and jump there */
            pc = find_next_target(fc, pc);
            if (pc == 0xFFFFFFFF) break;  /* All targets processed */
            
            /* Load frame at this target */
            restore_frame(fc, pc);
            continue;
        }
        
        pc += get_inst_len(bytecode, pc, bytecode_len);
    }
    
    /* Step 4: Sort frames by PC for encoding */
    sort_frames_by_pc(fc);
    
    return 0;
}

static void save_frame(frame_computer_t *fc, u4 pc)
{
    if (fc->frame_count >= fc->frame_capacity) {
        fc->frame_capacity *= 2;
        frame_state_t *new_frames = arena_alloc(fc->arena,
                                               fc->frame_capacity * sizeof(frame_state_t));
        memcpy(new_frames, fc->frames, fc->frame_count * sizeof(frame_state_t));
        fc->frames = new_frames;
    }
    
    /* Copy current frame */
    fc->frames[fc->frame_count] = fc->current_frame;
    fc->frames[fc->frame_count].pc = pc;
    fc->frame_count++;
}
```

**Estimated effort:** 6-8 hours

---

## Phase 6: StackMapTable Encoding

```c
/* Encode as StackMapTable attribute (FULL_FRAME only) */
int fc_encode_stackmap_table(frame_computer_t *fc,
                             u1 **output,
                             u4 *output_len)
{
    /* Calculate size needed */
    u4 size = 2;  /* number_of_entries */
    
    for (u4 i = 0; i < fc->frame_count; i++) {
        size += 1;  /* frame_type (255) */
        size += 2;  /* offset_delta */
        size += 2;  /* locals_count */
        size += count_verification_info_size(&fc->frames[i].locals, 
                                            fc->frames[i].locals_count);
        size += 2;  /* stack_count */
        size += count_verification_info_size(&fc->frames[i].stack,
                                            fc->frames[i].stack_count);
    }
    
    u1 *data = arena_alloc(fc->arena, size);
    int offset = 0;
    
    /* Write number of frames */
    write_u2_and_advance(data, &offset, fc->frame_count);
    
    u4 prev_pc = 0;
    for (u4 i = 0; i < fc->frame_count; i++) {
        frame_state_t *frame = &fc->frames[i];
        
        /* FULL_FRAME */
        write_u1_and_advance(data, &offset, 255);
        
        /* offset_delta */
        u2 delta = (i == 0) ? frame->pc : (frame->pc - prev_pc - 1);
        write_u2_and_advance(data, &offset, delta);
        prev_pc = frame->pc;
        
        /* Locals */
        write_u2_and_advance(data, &offset, frame->locals_count);
        encode_verification_types(data, &offset, frame->locals, frame->locals_count);
        
        /* Stack */
        write_u2_and_advance(data, &offset, frame->stack_count);
        encode_verification_types(data, &offset, frame->stack, frame->stack_count);
    }
    
    *output = data;
    *output_len = offset;
    return 0;
}

static void encode_verification_types(u1 *data, int *offset,
                                     const verification_type_t *types,
                                     u2 count)
{
    for (u2 i = 0; i < count; i++) {
        write_u1_and_advance(data, offset, types[i].type);
        
        if (types[i].type == ITEM_Object) {
            write_u2_and_advance(data, offset, types[i].cpool_index);
        } else if (types[i].type == ITEM_Uninitialized) {
            write_u2_and_advance(data, offset, types[i].offset);
        }
    }
}
```

**Estimated effort:** 4-5 hours

---

## Phase 7: Integration with Injection

### Modify `lib/jvm/injection.c`

```c
static int create_new_code_attribute(/* ... */)
{
    /* ... existing code ... */
    
    /* Generate StackMapTable if class version >= 50 */
    u1 *stackmap_data = NULL;
    u4 stackmap_len = 0;
    
    if (cf->major_version >= 50) {
        frame_computer_t *fc = fc_create(arena, cf);
        if (!fc) return BYTECODE_ERROR_MEMORY_ALLOCATION;
        
        if (fc_compute_frames(fc, bb->buf, bb->len, orig_info) != 0) {
            /* Frame computation failed - skip this method */
            LOG_WARN("Failed to compute frames for method");
            return BYTECODE_ERROR_INVALID_BYTECODE;
        }
        
        if (fc_encode_stackmap_table(fc, &stackmap_data, &stackmap_len) != 0) {
            return BYTECODE_ERROR_MEMORY_ALLOCATION;
        }
    }
    
    /* Update attribute count and add StackMapTable */
    u2 attr_count = (stackmap_data != NULL) ? 1 : 0;
    write_u2_and_advance(new_attr_data, &offset, attr_count);
    
    if (stackmap_data) {
        /* Add StackMapTable attribute */
        u2 stackmap_name_index = injection_find_or_add_utf8_constant(
            arena, cf, "StackMapTable");
        write_u2_and_advance(new_attr_data, &offset, stackmap_name_index);
        write_u4_and_advance(new_attr_data, &offset, stackmap_len);
        memcpy(&new_attr_data[offset], stackmap_data, stackmap_len);
        offset += stackmap_len;
    }
    
    /* ... rest of function ... */
}
```

**Estimated effort:** 2-3 hours

---

## Phase 8: Testing Strategy

### Test Suite Structure

**File:** `test/test_stackmap.c`

```c
/* Unit tests */
void test_simple_arithmetic(void);      /* iconst, iadd, ireturn */
void test_control_flow(void);           /* if, goto */
void test_method_calls(void);           /* invokestatic, invokevirtual */
void test_exception_handlers(void);     /* try-catch blocks */
void test_switches(void);               /* tableswitch, lookupswitch */

/* Integration tests */
void test_inject_simple_method(void);   /* Method without branches */
void test_inject_with_loop(void);       /* Method with loops */
void test_inject_with_exceptions(void); /* Method with try-catch */
```

### Validation

1. **Unit test each opcode simulation**: Verify stack/locals after each instruction
2. **Compare with javap output**: Parse existing StackMapTable and compare with generated
3. **Live JVM validation**: Load generated class and verify it doesn't throw VerifyError
4. **Spring Boot integration**: Test on real Spring Boot application

**Estimated effort:** 8-10 hours

---

## Implementation Timeline

| Phase | Task | Lines of Code | Time Estimate |
|-------|------|---------------|---------------|
| 1 | Extend opcode.def | 200 | 2-3 hours |
| 2 | Data structures | 150 | 1 hour |
| 3 | Instruction simulation | 600 | 12-16 hours |
| 4 | Control flow analysis | 200 | 3-4 hours |
| 5 | Frame computation | 300 | 6-8 hours |
| 6 | StackMapTable encoding | 200 | 4-5 hours |
| 7 | Integration | 100 | 2-3 hours |
| 8 | Testing | 300 | 8-10 hours |
| **Total** | | **~2050** | **38-50 hours** |

---

## Known Limitations

1. **JSR/RET subroutines**: Deprecated since Java 7, not implemented (very rare)
2. **Uninitialized objects**: `new` instruction tracking requires additional state
3. **Frame merging**: Not implemented (FULL_FRAME approach doesn't require it)
4. **Dead code**: Unreachable code after `return`/`athrow` may cause issues

---

## Files to Create/Modify

### New Files
- `lib/jvm/stackmap.h` - Public API
- `lib/jvm/stackmap.c` - Implementation (~1500 lines)
- `test/test_stackmap.c` - Test suite (~300 lines)

### Modified Files
- `lib/jvm/opcode.def` - Add stack effect metadata
- `lib/jvm/opcode.h` - Generate new lookup tables
- `lib/jvm/injection.c` - Integrate StackMapTable generation
- `lib/jvm/injection.h` - Expose new flags

---

## Success Criteria

- [ ] All JVM opcodes have stack effect metadata in opcode.def
- [ ] Instruction simulator handles 200+ opcodes correctly
- [ ] Control flow analysis identifies all branch targets
- [ ] Frame computation produces valid FULL_FRAME entries
- [ ] Generated StackMapTable passes JVM verifier
- [ ] Spring Boot application starts successfully with instrumented classes
- [ ] No VerifyError exceptions during runtime

---

## Fallback Strategy

If full implementation proves too complex:
1. Implement only for methods without exception handlers (simpler control flow)
2. Use class version downgrade (50.0) for complex methods
3. Hybrid approach: Generate frames where possible, downgrade when failing

This incremental approach maintains working instrumentation throughout development.

---

## References

- [JVM Specification §4.7.4 - StackMapTable Attribute](https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7.4)
- [JVM Specification §4.10.1 - Verification by Type Checking](https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.10.1)
- [ASM Library - Frame Computation](https://asm.ow2.io/javadoc/org/objectweb/asm/MethodWriter.html)
