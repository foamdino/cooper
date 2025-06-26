/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cache.h"

#define MAX_TLS_CACHES 8  /**< Maximum number of different cache types per thread */

typedef struct tls_cache_entry tls_cache_entry_t;

struct tls_cache_entry 
{
    char cache_id[32];      /**< Cache identifier */
    cache_t *cache;         /**< Cache instance */
};

typedef struct tls_cache_manager tls_cache_manager_t;

struct tls_cache_manager 
{
    tls_cache_entry_t caches[MAX_TLS_CACHES];
    size_t count;
    size_t hits;            /**< Global hit counter for this thread */
    size_t misses;          /**< Global miss counter for this thread */
};

/* Thread-local storage */
static pthread_key_t tls_cache_key;
static pthread_once_t tls_init_once = PTHREAD_ONCE_INIT;

/* Have we called the cleanup function? */
static int tls_cleaned_up = 0;

/* Global cache arena - set during initialization */
static arena_t *cache_arena = NULL;

int cache_init_system(arena_t *arena)
{
    if (cache_arena != NULL)
        return 0;

    cache_arena = arena;
    return cache_tls_init();
}

/* Default memory copy function */
static void default_copy(void *dest, const void *src, size_t size)
{
    memcpy(dest, src, size);
}

cache_t *cache_init(arena_t *arena, const cache_config_t *config)
{
    assert(arena != NULL);
    assert(config != NULL);

    if (!arena || !config || config->max_entries == 0 || 
        config->key_size == 0 || config->value_size == 0 || !config->key_compare) {
        return NULL;
    }

    cache_t *cache = arena_alloc(arena, sizeof(cache_t));
    if (!cache) return NULL;

    /* Allocate entries array */
    cache->entries = arena_alloc(arena, config->max_entries * sizeof(cache_entry_t));
    if (!cache->entries) return NULL;

    /* Allocate memory for all keys and values in one block for better locality */
    size_t total_key_memory = config->max_entries * config->key_size;
    size_t total_value_memory = config->max_entries * config->value_size;
    
    void *key_memory = arena_alloc(arena, total_key_memory);
    if (!key_memory) return NULL;
    
    void *value_memory = arena_alloc(arena, total_value_memory);
    if (!value_memory) return NULL;

    /* Initialize cache */
    cache->capacity = config->max_entries;
    cache->count = 0;
    cache->next_victim = 0;
    cache->config = *config;
    cache->arena = arena;

    /* Set up default copy functions if not provided */
    if (!cache->config.key_copy)
        cache->config.key_copy = default_copy;
    
    if (!cache->config.value_copy)
        cache->config.value_copy = default_copy;

    /* Initialize entries */
    for (size_t i = 0; i < config->max_entries; i++) 
    {
        cache->entries[i].key = (char*)key_memory + (i * config->key_size);
        cache->entries[i].value = (char*)value_memory + (i * config->value_size);
        cache->entries[i].valid = 0;
        
        if (config->entry_init)
            config->entry_init(&cache->entries[i]);
    }

    return cache;
}

/**
 * Get an entry from the cache
 * 
 * @param cache     Cache instance
 * @param key       Key to search for
 * @param value     Output buffer for value (if found)
 * @return          0 if found, 1 if not found or error
 */
int cache_get(cache_t *cache, const void *key, void *value)
{
    if (!cache || !key) return 1;

    /* Linear search through valid entries */
    for (size_t i = 0; i < cache->capacity; i++) 
    {
        if (cache->entries[i].valid && 
            cache->config.key_compare(cache->entries[i].key, key) == 0) {
            
            /* Found - copy value if requested */
            if (value)
                cache->config.value_copy(value, cache->entries[i].value, cache->config.value_size);
            
            return 0; /* Found */
        }
    }

    return 1; /* Not found */
}

/**
 * Add an entry to the cache, will overwrite an exsiting key
 * 
 * @param cache pointer to cache_t
 * @param key void pointer as cache key
 * @param value void pointer as value
 * 
 * @return 1 on failure, 0 on success
 */
int cache_put(cache_t *cache, const void *key, const void *value)
{
    if (!cache || !key || !value) 
        return 1;

    /* First check if key already exists */
    for (size_t i = 0; i < cache->capacity; i++) 
    {
        if (cache->entries[i].valid && 
            cache->config.key_compare(cache->entries[i].key, key) == 0) {
            
            /* Update existing entry */
            cache->config.value_copy(cache->entries[i].value, value, cache->config.value_size);
            return 0;
        }
    }

    /* Find an empty slot or evict */
    size_t target_index;
    if (cache->count < cache->capacity) {
        /* Find first empty slot */
        for (target_index = 0; target_index < cache->capacity; target_index++) 
        {
            if (!cache->entries[target_index].valid)
                break;
        }
        cache->count++;
    } 
    else 
    {
        /* Cache is full, use round-robin eviction */
        target_index = cache->next_victim;
        cache->next_victim = (cache->next_victim + 1) % cache->capacity;
    }

    /* Insert new entry */
    cache->entries[target_index].valid = 1;
    cache->config.key_copy(cache->entries[target_index].key, key, cache->config.key_size);
    cache->config.value_copy(cache->entries[target_index].value, value, cache->config.value_size);

    return 0;
}

void cache_clear(cache_t *cache)
{
    /* Clearing a NULL cache does nothing */
    if (!cache) 
        return;

    for (size_t i = 0; i < cache->capacity; i++)
        cache->entries[i].valid = 0;

    
    cache->count = 0;
    cache->next_victim = 0;
}

void cache_stats(cache_t *cache, size_t *hits, size_t *misses, size_t *entries)
{
    if (!cache) 
        return;

    if (entries)
        *entries = cache->count;

    /* Note: Individual cache instances don't track hits/misses to keep them lightweight.
       Hit/miss tracking is done at the thread level by the TLS manager. */
    if (hits) 
        *hits = 0;

    if (misses) 
        *misses = 0;
}

/* Thread-local cache management */
static void cache_tls_init_once(void)
{
    pthread_key_create(&tls_cache_key, NULL);
}

int cache_tls_init(void)
{
    if (tls_cleaned_up) {
        return 1; /* Cannot reinitialize after cleanup */
    }

    int result = pthread_once(&tls_init_once, cache_tls_init_once);
    return (result == 0) ? 0 : 1;
}

cache_t *cache_tls_get(const char *cache_id, arena_t *data_arena, const cache_config_t *config)
{
    assert(cache_id != NULL);
    assert(data_arena != NULL);
    /* the cache arena must be initialised first */
    assert(cache_arena != NULL);

    if (!cache_id) 
        return NULL;

    if (cache_tls_init() != 0) 
        return NULL;

    tls_cache_manager_t *manager = pthread_getspecific(tls_cache_key);
    if (!manager) 
    {
        /* First time - create manager */
        manager = arena_alloc(cache_arena, sizeof(tls_cache_manager_t));
        if (!manager) 
            return NULL;

        /* Initialise the manager */
        memset(manager, 0, sizeof(tls_cache_manager_t));

        if (pthread_setspecific(tls_cache_key, manager) != 0)
            return NULL;
    }

    /* Look for existing cache */
    for (size_t i = 0; i < manager->count; i++) 
    {
        if (strcmp(manager->caches[i].cache_id, cache_id) == 0)
            return manager->caches[i].cache;
    }

    /* Need to create new cache */
    if (manager->count >= MAX_TLS_CACHES || !config)
        return NULL;

    cache_t *new_cache = cache_init(data_arena, config);
    if (!new_cache) 
        return NULL;

    /* Add to manager */
    size_t index = manager->count;
    strncpy(manager->caches[index].cache_id, cache_id, sizeof(manager->caches[index].cache_id) - 1);
    manager->caches[index].cache_id[sizeof(manager->caches[index].cache_id) - 1] = '\0';
    manager->caches[index].cache = new_cache;
    manager->count++;

    return new_cache;
}

void cache_tls_cleanup(void)
{
    if (!tls_cleaned_up) 
    {
        pthread_key_delete(tls_cache_key);
        tls_cleaned_up = 1;
        cache_arena = NULL;
    }
}