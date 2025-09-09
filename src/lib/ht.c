/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ht.h"
#include "log.h"
#include <string.h>
#include <assert.h>

/* djb2 hash function for strings */
static size_t
ht_hash_string(const char *str, size_t capacity)
{
	assert(str != NULL);
	assert(capacity > 0);

	size_t hash = 5381;
	int c;
	while ((c = *str++))
	{
		hash = ((hash << 5) + hash) + c;
	}
	return hash % capacity;
}

/* Find entry index for key (linear probing with tombstone support) */
static size_t
ht_find_slot(hashtable_t *ht, const char *key, int *found)
{
	assert(ht != NULL);
	assert(ht->entries != NULL);
	assert(key != NULL);
	assert(found != NULL);

	size_t hash          = ht_hash_string(key, ht->capacity);
	*found               = 0;
	size_t first_deleted = ht->capacity; /* Track first deleted slot for insertion */

	/* Linear probing with wraparound */
	for (size_t i = 0; i < ht->capacity; i++)
	{
		size_t idx        = (hash + i) % ht->capacity;
		ht_entry_t *entry = &ht->entries[idx];

		if (entry->state == HT_EMPTY)
		{
			/* Empty slot found - can use for insertion */
			return (first_deleted < ht->capacity) ? first_deleted : idx;
		}

		if (entry->state == HT_DELETED && first_deleted == ht->capacity)
		{
			/* Remember first deleted slot for potential insertion */
			first_deleted = idx;
		}

		if (entry->state == HT_OCCUPIED && entry->key
		    && strcmp(entry->key, key) == 0)
		{
			/* Key exists */
			*found = 1;
			return idx;
		}
	}

	/* Table full or return first deleted slot for insertion */
	return first_deleted;
}

hashtable_t *
ht_create(arena_t *arena, size_t initial_cap, double load_factor)
{
	assert(arena != NULL);
	assert(initial_cap > 0);
	assert(load_factor > 0.0 && load_factor <= 1.0);

	/* Validate parameters */
	if (!arena || initial_cap == 0 || load_factor <= 0.0 || load_factor >= 1.0)
	{
		LOG_ERROR("Invalid hashtable parameters");
		return NULL;
	}

	/* Allocate hashtable structure */
	hashtable_t *ht = arena_alloc(arena, sizeof(hashtable_t));
	if (!ht)
	{
		LOG_ERROR("Failed to allocate hashtable structure");
		return NULL;
	}

	/* Allocate entries array */
	size_t entries_size = initial_cap * sizeof(ht_entry_t);
	ht->entries         = arena_alloc(arena, entries_size);
	if (!ht->entries)
	{
		LOG_ERROR("Failed to allocate hashtable entries");
		return NULL;
	}

	/* Initialize structure */
	ht->capacity    = initial_cap;
	ht->load_factor = load_factor;
	ht->arena       = arena;

	LOG_INFO("Created hashtable: capacity=%zu, load_factor=%.2f",
	         initial_cap,
	         load_factor);
	return ht;
}

int
ht_put(hashtable_t *ht, const char *key, void *value)
{
	/* Validate parameters */
	if (!ht || !ht->entries || !key || key[0] == '\0')
	{
		LOG_ERROR("Invalid parameters to ht_put");
		return 1;
	}

	/* Check load factor before insertion */
	double current_load = (double)ht->count / ht->capacity;
	if (current_load >= ht->load_factor)
	{
		LOG_WARN("Hashtable load factor exceeded: %.2f >= %.2f",
		         current_load,
		         ht->load_factor);
		return 1;
	}

	/* Find slot for key */
	int found;
	size_t idx = ht_find_slot(ht, key, &found);

	if (idx >= ht->capacity)
	{
		LOG_ERROR("Hashtable full, cannot insert key: %s", key);
		return 1;
	}

	ht_entry_t *entry = &ht->entries[idx];

	if (found)
	{
		/* Update existing entry */
		entry->value = value;
		LOG_DEBUG("Updated existing key: %s", key);
	}
	else
	{
		/* Create new entry */
		size_t key_len = strlen(key);
		entry->key     = arena_alloc(ht->arena, key_len + 1);
		if (!entry->key)
		{
			LOG_ERROR("Failed to allocate key storage");
			return 1;
		}

		/* Safe string copy */
		memcpy(entry->key, key, key_len);
		entry->key[key_len] = '\0';

		entry->value = value;
		entry->state = HT_OCCUPIED;
		ht->count++;

		LOG_DEBUG("Inserted new key: %s (count: %zu/%zu)",
		          key,
		          ht->count,
		          ht->capacity);
	}

	return 0;
}

void *
ht_get(hashtable_t *ht, const char *key)
{
	/* Validate parameters */
	if (!ht || !ht->entries || !key || key[0] == '\0')
		return NULL;

	/* Find entry */
	int found;
	size_t idx = ht_find_slot(ht, key, &found);

	if (found && idx < ht->capacity)
		return ht->entries[idx].value;

	return NULL;
}

int
ht_remove(hashtable_t *ht, const char *key)
{
	/* Validate parameters */
	if (!ht || !ht->entries || !key || key[0] == '\0')
	{
		return 1;
	}

	/* Find entry */
	int found;
	size_t idx = ht_find_slot(ht, key, &found);

	if (!found || idx >= ht->capacity)
	{
		return 1;
	}

	/* Mark as deleted (tombstone) - preserves probe chain */
	ht_entry_t *entry = &ht->entries[idx];
	entry->key        = NULL;
	entry->value      = NULL;
	entry->state      = HT_DELETED;
	ht->count--;

	LOG_DEBUG("Removed key: %s (count: %zu/%zu)", key, ht->count, ht->capacity);
	return 0;
}

double
ht_get_load(hashtable_t *ht)
{
	if (!ht || ht->capacity == 0)
	{
		return 0.0;
	}
	return (double)ht->count / ht->capacity;
}

void
ht_reset(hashtable_t *ht)
{
	/* We have no ht so do nothing */
	if (!ht || !ht->entries)
		return;

	/* Reset all entries - memset to 0 sets all states to HT_EMPTY */
	memset(ht->entries, 0, ht->capacity * sizeof(ht_entry_t));

	ht->count = 0;
	LOG_INFO("Reset hashtable (capacity: %zu)", ht->capacity);
}