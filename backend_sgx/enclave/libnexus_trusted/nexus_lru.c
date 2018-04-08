#include <string.h>

#include "nexus_lru.h"
#include "nexus_hashtable.h"
#include "nexus_util.h"

#include "nexus_log.h"

#include "list.h"


struct nexus_lru {
    size_t count;
    size_t capacity;

    lru_freer freer;

    struct nexus_hashtable * htable;

    struct list_head list;
};

struct lru_node {
    uintptr_t key;
    uintptr_t value;

    struct list_head node;
};


static void
free_lru_node(struct nexus_lru * lru, struct lru_node * lru_node)
{
    if (lru->freer) {
        lru->freer(lru_node->value, lru_node->key);
    }

    list_del(&(lru_node->node));
    nexus_free(lru_node);

    lru->count -= 1;
}



struct nexus_lru *
nexus_lru_create(size_t capacity, lru_hasher hasher, lru_comparer comparer, lru_freer freer)
{
    struct nexus_lru * lru = nexus_malloc(sizeof(struct nexus_lru));

    INIT_LIST_HEAD(&(lru->list));

    lru->htable = nexus_create_htable(capacity, hasher, comparer);

    if (lru->htable == NULL) {
        log_error("could not create hashtable\n");

        nexus_free(lru);
        return NULL;
    }

    lru->freer = freer;

    return lru;
}

void
nexus_lru_destroy(struct nexus_lru * lru)
{
    while (!list_empty(&lru->list)) {
        struct lru_node * lru_node = list_first_entry(&(lru->list), struct lru_node, node);

        free_lru_node(lru, lru_node);
    }

    nexus_free_htable(lru->htable, 0, 0);
    nexus_free(lru);
}

size_t
nexus_lru_count(struct nexus_lru * lru)
{
    return lru->count;
}

void *
nexus_lru_get(struct nexus_lru * lru, void * key)
{
    struct lru_node * lru_node = (struct lru_node *)nexus_htable_search(lru->htable, (uintptr_t)key);

    if (lru_node == NULL) {
        return NULL;
    }

    // move the item to the front
    list_move(&(lru_node->node), &(lru->list));

    return (void *) lru_node->value;
}

static void
try_shrinking_lru(struct nexus_lru * lru)
{
    struct lru_node * lru_node = NULL;

    if (lru->count < lru->capacity) {
        return;
    }

    lru_node = list_last_entry(&(lru->list), struct lru_node, node);

    nexus_htable_remove(lru->htable, lru_node->key, 0);

    free_lru_node(lru, lru_node);
}

bool
nexus_lru_put(struct nexus_lru * lru, void * key, void * value)
{
    struct lru_node * lru_node = (struct lru_node *)nexus_htable_search(lru->htable, (uintptr_t)key);

    if (lru_node == NULL) {
        try_shrinking_lru(lru);

        lru_node        = nexus_malloc(sizeof(struct lru_node));
        lru_node->value = (uintptr_t)value;
        lru_node->key   = (uintptr_t)key;

        list_add(&(lru_node->node), &(lru->list));
        nexus_htable_insert(lru->htable, lru_node->key, lru_node->value);
        lru->count += 1;

        return true;
    }

    // replace value and move shit to the front
    lru->freer(lru_node->value, lru_node->key);

    lru_node->value = (uintptr_t)value;

    list_move(&(lru_node->node), &(lru->list));

    return true;
}

void
nexus_lru_del(struct nexus_lru * lru, void * key)
{
    struct lru_node * lru_node = (struct lru_node *)nexus_htable_remove(lru->htable, (uintptr_t)key, 0);

    if (lru_node) {
        free_lru_node(lru, lru_node);
    }
}
