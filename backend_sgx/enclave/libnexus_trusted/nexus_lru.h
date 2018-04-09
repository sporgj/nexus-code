/**
 * Copyright (C) 2018 Judicael Djoko <sporgj@gmail.com>
 *
 * A simple lru object store
 */
#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct nexus_lru;


typedef uint32_t (*lru_hasher)   (uintptr_t key);
typedef int      (*lru_comparer) (uintptr_t key1, uintptr_t key2);
typedef void     (*lru_freer)    (uintptr_t element, uintptr_t key); // key can be NULL


/**
 * Creates a new LRU cache with the specified capacity
 * @param capacity
 * @param hasher
 * @param comparer
 * @parma freer
 * @return lru
 */
struct nexus_lru *
nexus_lru_create(size_t capacity, lru_hasher hasher, lru_comparer comparer, lru_freer freer);

/**
 * Destroys a created LRU
 * @param lru
 */
void
nexus_lru_destroy(struct nexus_lru * lru);

/**
 * Returns the number of items in the LRU
 * @param lru
 */
size_t
nexus_lru_count(struct nexus_lru * lru);

/**
 * Gets item within LRU
 * @param lru
 * @param key
 */
void *
nexus_lru_get(struct nexus_lru * lru, void * key);

/**
 * Puts an item in the lru. If it exists, takes item to the front of the queue
 * @param lru
 * @param key
 * @param value
 * @return true if the insertion succeeded
 */
bool
nexus_lru_put(struct nexus_lru * lru, void * key, void * value);

/**
 * Deletes the key from the LRU
 * @param lru
 * @param kry
 */
void
nexus_lru_del(struct nexus_lru * lru, void * key);
