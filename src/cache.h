/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <pthread.h>
#include "arena.h"

typedef struct cache_entry cache_entry_t;
typedef struct cache cache_t;
typedef struct cache_config cache_config_t;

/* Function pointer types for cache operations */
typedef int (*cache_key_compare_fn)(const void *key1, const void *key2);
typedef void (*cache_entry_copy_fn)(void *dest, const void *src, size_t size);
typedef void (*cache_entry_init_fn)(void *entry);

struct cache_entry 
{
    void *key;              /**< Cache key */
    void *value;            /**< Cache value */
    int valid;              /**< Whether this entry is valid */
};

struct cache_config {
    size_t max_entries;     /**< Maximum number of cache entries */
    size_t key_size;        /**< Size of cache key in bytes */
    size_t value_size;      /**< Size of cache value in bytes */
    cache_key_compare_fn key_compare;  /**< Function to compare keys */
    cache_entry_copy_fn key_copy;      /**< Function to copy keys */
    cache_entry_copy_fn value_copy;    /**< Function to copy values */
    cache_entry_init_fn entry_init;    /**< Optional entry initialization */
    const char *name;       /**< Cache name for debugging */
};

struct cache {
    cache_entry_t *entries; /**< Array of cache entries */
    size_t capacity;        /**< Maximum number of entries */
    size_t count;           /**< Current number of valid entries */
    size_t next_victim;     /**< Next entry to evict (round-robin) */
    cache_config_t config;  /**< Cache configuration */
    arena_t *arena;         /**< Arena for memory allocation */
};

/**
 * Initialize a new cache instance
 * 
 * @param arena     Arena to use for allocations
 * @param config    Cache configuration
 * @return          Pointer to initialized cache, or NULL on failure
 */
cache_t *cache_init(arena_t *arena, const cache_config_t *config);

/**
 * Get an entry from the cache
 * 
 * @param cache     Cache instance
 * @param key       Key to search for
 * @param value     Output buffer for value (if found)
 * @return          1 if found, 0 if not found
 */
int cache_get(cache_t *cache, const void *key, void *value);

/**
 * Put an entry into the cache
 * 
 * @param cache     Cache instance
 * @param key       Key to store
 * @param value     Value to store
 * @return          1 on success, 0 on failure
 */
int cache_put(cache_t *cache, const void *key, const void *value);

/**
 * Clear all entries in the cache
 * 
 * @param cache     Cache instance
 */
void cache_clear(cache_t *cache);

/**
 * Get cache statistics
 * 
 * @param cache     Cache instance
 * @param hits      Output: number of cache hits (can be NULL)
 * @param misses    Output: number of cache misses (can be NULL)
 * @param entries   Output: current number of entries (can be NULL)
 */
void cache_stats(cache_t *cache, size_t *hits, size_t *misses, size_t *entries);

/* Thread-local cache management */

/**
 * Initialize thread-local cache system
 * 
 * @return 0 on success, non-zero on failure
 */
int cache_tls_init(void);

/**
 * Get thread-local cache instance
 * 
 * @param cache_id  Unique identifier for this cache type
 * @param arena     Arena to use for allocation (if creating new cache)
 * @param config    Configuration (if creating new cache)
 * @return          Thread-local cache instance, or NULL on failure
 */
cache_t *cache_tls_get(const char *cache_id, arena_t *arena, const cache_config_t *config);

/**
 * Cleanup thread-local cache system
 */
void cache_tls_cleanup(void);

#endif /* CACHE_H */