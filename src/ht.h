/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HT_H
#define HT_H

#include <stddef.h>
#include <stdint.h>
#include "arena.h"

/* Entry states for tombstone deletion */
#define HT_EMPTY    0
#define HT_OCCUPIED 1
#define HT_DELETED  2

/* Forward declarations */
typedef struct ht_entry ht_entry_t;
typedef struct hashtable hashtable_t;

/* Hashtable entry structure */
struct ht_entry 
{
    char *key;              /* String key (arena-allocated) */
    void *value;            /* Generic value pointer */
    uint8_t state;          /* 0=empty, 1=occupied, 2=deleted */
};

/* Main hashtable structure */
struct hashtable 
{
    ht_entry_t *entries;    /* Array of entries (arena-allocated) */
    size_t capacity;        /* Total number of slots */
    size_t count;           /* Number of occupied slots */
    double load_factor;     /* Maximum load factor before full */
    arena_t *arena;         /* Arena for memory allocation */
};

/* Creation and destruction */
/* NOTE: All functions are LOCK-FREE - caller must handle synchronization */

/**
 * Create a new hashtable using arena allocation
 * 
 * @param arena         Arena to use for all allocations  
 * @param initial_cap   Initial capacity (must be > 0)
 * @param load_factor   Load factor threshold (0.5 - 0.9 recommended)
 * 
 * @return              Hashtable pointer or NULL on failure
 * 
 * NOTE: LOCK-FREE - caller must ensure thread safety
 */
hashtable_t *ht_create(arena_t *arena, size_t initial_cap, double load_factor);

/**
 * Insert or update a key-value pair
 * 
 * @param ht            Hashtable pointer  
 * @param key           String key (will be copied to arena)
 * @param value         Value pointer to store
 * 
 * @return              1 on success, 0 on failure (table full or invalid args)
 * 
 * NOTE: LOCK-FREE - caller must ensure thread safety
 */
int ht_put(hashtable_t *ht, const char *key, void *value);

/**
 * Retrieve value for given key
 * 
 * @param ht            Hashtable pointer
 * @param key           String key to lookup
 * 
 * @return              Value pointer or NULL if not found
 * 
 * NOTE: LOCK-FREE - caller must ensure thread safety
 */
void *ht_get(hashtable_t *ht, const char *key);

/**
 * Remove key-value pair
 * 
 * @param ht            Hashtable pointer
 * @param key           String key to remove
 * 
 * @return              1 if removed, 0 if not found
 * 
 * NOTE: LOCK-FREE - caller must ensure thread safety
 */
int ht_remove(hashtable_t *ht, const char *key);

/**
 * Get current load factor
 * 
 * @param ht            Hashtable pointer
 * 
 * @return              Current load factor (count/capacity)
 * 
 * NOTE: LOCK-FREE - caller must ensure thread safety
 */
double ht_get_load(hashtable_t *ht);

/**
 * Reset hashtable to empty state (keeps capacity)
 * 
 * @param ht            Hashtable pointer
 * 
 * NOTE: LOCK-FREE - caller must ensure thread safety
 */
void ht_reset(hashtable_t *ht);

#endif /* HT_H */