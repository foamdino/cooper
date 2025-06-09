/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* src/shared_mem.c */
#include "shared_mem.h"
#include "log.h"

/**
 * Initialize shared memory for the agent
 */
int cooper_shm_init_agent(cooper_shm_context_t *ctx) {
    assert(ctx != NULL);

    if (!ctx) 
        return -1;
    
    memset(ctx, 0, sizeof(cooper_shm_context_t));
    
    ctx->data_shm_size = sizeof(cooper_data_shm_t);
    ctx->status_shm_size = sizeof(cooper_status_shm_t);
    
    /* Create data shared memory (agent writes, CLI reads) */
    ctx->data_fd = shm_open(COOPER_DATA_SHM_NAME, O_CREAT | O_RDWR | O_EXCL, 0644);
    if (ctx->data_fd == -1) {
        /* Try to unlink and recreate */
        shm_unlink(COOPER_DATA_SHM_NAME);
        ctx->data_fd = shm_open(COOPER_DATA_SHM_NAME, O_CREAT | O_RDWR | O_EXCL, 0644);
        if (ctx->data_fd == -1) {
            LOG_ERROR("Failed to create data shared memory: %s", strerror(errno));
            return -1;
        }
    }
    
    if (ftruncate(ctx->data_fd, ctx->data_shm_size) == -1) {
        LOG_ERROR("Failed to set data shared memory size: %s", strerror(errno));
        goto error_cleanup;
    }
    
    ctx->data_shm = mmap(NULL, ctx->data_shm_size, PROT_READ | PROT_WRITE, 
                        MAP_SHARED, ctx->data_fd, 0);
    if (ctx->data_shm == MAP_FAILED) {
        LOG_ERROR("Failed to map data shared memory: %s", strerror(errno));
        goto error_cleanup;
    }
    
    /* Initialize data shared memory */
    memset(ctx->data_shm, 0, ctx->data_shm_size);
    ctx->data_shm->version = COOPER_SHM_VERSION;
    ctx->data_shm->max_entries = COOPER_MAX_ENTRIES;
    ctx->data_shm->start_time = time(NULL);
    ctx->data_shm->next_write_index = 0;
    
    /* Create status shared memory (CLI writes, agent reads) */
    ctx->status_fd = shm_open(COOPER_STATUS_SHM_NAME, O_CREAT | O_RDWR | O_EXCL, 0644);
    if (ctx->status_fd == -1) {
        shm_unlink(COOPER_STATUS_SHM_NAME);
        ctx->status_fd = shm_open(COOPER_STATUS_SHM_NAME, O_CREAT | O_RDWR | O_EXCL, 0644);
        if (ctx->status_fd == -1) {
            LOG_ERROR("Failed to create status shared memory: %s", strerror(errno));
            goto error_cleanup;
        }
    }
    
    if (ftruncate(ctx->status_fd, ctx->status_shm_size) == -1) {
        LOG_ERROR("Failed to set status shared memory size: %s", strerror(errno));
        goto error_cleanup;
    }
    
    ctx->status_shm = mmap(NULL, ctx->status_shm_size, PROT_READ | PROT_WRITE, 
                          MAP_SHARED, ctx->status_fd, 0);
    if (ctx->status_shm == MAP_FAILED) {
        LOG_ERROR("Failed to map status shared memory: %s", strerror(errno));
        goto error_cleanup;
    }
    
    /* Initialize status shared memory */
    memset(ctx->status_shm, 0, ctx->status_shm_size);
    for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++) {
        ctx->status_shm->status[i] = ENTRY_EMPTY;
    }
    
    LOG_INFO("Shared memory initialized successfully");
    return 0;
    
error_cleanup:
    cooper_shm_cleanup_agent(ctx);
    return -1;
}

/**
 * Write method metric to shared memory
 */
int cooper_shm_write_method_metric(cooper_shm_context_t *ctx, const cooper_method_metric_data_t *metric) 
{
    assert(ctx != NULL);
    assert(metric != NULL);
    assert(ctx->data_shm != NULL);      /* Context should be initialized */
    assert(ctx->status_shm != NULL);    /* Context should be initialized */
    assert(metric->data_type == COOPER_DATA_METHOD_METRIC); /* Correct data type */
    assert(strlen(metric->signature) > 0); /* Non-empty signature */

    if (!ctx || !metric) return -1;
    
    uint32_t write_index = ctx->data_shm->next_write_index % COOPER_MAX_ENTRIES;
    
    /* Check if CLI has read the previous data at this index */
    if (ctx->status_shm->status[write_index] == ENTRY_READY) {
        /* CLI hasn't read previous data yet, skip this write */
        return -1;
    }
    
    /* Write the metric data */
    memcpy(&ctx->data_shm->metrics[write_index], metric, sizeof(*metric));

    /* Mark as ready for CLI to read */
    ctx->status_shm->status[write_index] = ENTRY_READY;
    
    /* Update write index for next time */
    ctx->data_shm->next_write_index = (write_index + 1) % COOPER_MAX_ENTRIES;
    
    return 0;
}

/**
 * Write memory sample to shared memory
 * For simplicity, we'll store it in the same array but with different data_type
 */
int cooper_shm_write_memory_sample(cooper_shm_context_t *ctx, const cooper_memory_sample_data_t *sample) 
{
    assert(ctx != NULL);
    assert(sample != NULL);
    assert(ctx->data_shm != NULL);      /* Context should be initialized */
    assert(ctx->status_shm != NULL);    /* Context should be initialized */
    assert(sample->data_type == COOPER_DATA_MEMORY_SAMPLE); /* Correct data type */
    assert(sample->process_memory != UINT64_MAX);  /* Not uninitialized */
    assert(sample->thread_memory != UINT64_MAX);   /* Not uninitialized */

    if (!ctx || !sample) 
        return -1;
    
    uint32_t write_index = ctx->data_shm->next_write_index % COOPER_MAX_ENTRIES;
    
    if (ctx->status_shm->status[write_index] == ENTRY_READY) {
        return -1;
    }
    
    /* Store memory sample in metrics array - reuse the structure */
    cooper_method_metric_data_t *entry = &ctx->data_shm->metrics[write_index];
    memset(entry, 0, sizeof(*entry));
    
    snprintf(entry->signature, sizeof(entry->signature), "memory_sample");
    entry->data_type = COOPER_DATA_MEMORY_SAMPLE;
    entry->timestamp = sample->timestamp;
    entry->alloc_bytes = sample->process_memory;
    entry->call_count = sample->thread_id;
    entry->peak_memory = sample->thread_memory;

    /* Mark as ready for CLI to read */
    ctx->status_shm->status[write_index] = ENTRY_READY;
    
    ctx->data_shm->next_write_index = (write_index + 1) % COOPER_MAX_ENTRIES;
    
    return 0;
}

/**
 * Check status array and reset entries that CLI has read
 */
void cooper_shm_cleanup_read_entries(cooper_shm_context_t *ctx) 
{
    assert(ctx != NULL);

    if (!ctx) 
        return;
    
    for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++) {
        if (ctx->status_shm->status[i] == ENTRY_READ) {
            ctx->status_shm->status[i] = ENTRY_EMPTY;
        }
    }
}

/**
 * Cleanup shared memory resources
 */
int cooper_shm_cleanup_agent(cooper_shm_context_t *ctx) 
{
    assert(ctx != NULL);

    if (!ctx) 
        return 0;
    
    /* Unmap memory */
    if (ctx->data_shm && ctx->data_shm != MAP_FAILED)
        munmap(ctx->data_shm, ctx->data_shm_size);
    
    if (ctx->status_shm && ctx->status_shm != MAP_FAILED)
        munmap(ctx->status_shm, ctx->status_shm_size);
    
    /* Close file descriptors */
    if (ctx->data_fd > 0)
        close(ctx->data_fd);

    if (ctx->status_fd > 0)
        close(ctx->status_fd);
    
    /* Unlink shared memory objects */
    shm_unlink(COOPER_DATA_SHM_NAME);
    shm_unlink(COOPER_STATUS_SHM_NAME);
    
    memset(ctx, 0, sizeof(cooper_shm_context_t));
    
    LOG_INFO("Shared memory cleanup completed");
    return 0;
}