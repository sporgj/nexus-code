/**
 * Copyright (C) 2018 Judicael Djoko <sporgj@gmail.com>
 *
 * This file leverages list_head defined in list.h to provide a simplified interface
 * to a list. Features such as multithreading, sorting etc. will be added.
 *
 * This is free software. You are permitted to use, redistribute, and modify it.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "list.h"

typedef void (*list_deallocator)(void * element);

struct nexus_list_iterator;

struct nexus_list {
    struct list_head list;

    struct {
        list_deallocator deallocator;
    } attrs;
};

/**
 * Initializes an empty list
 * @param list
 */
void
nexus_list_init(struct nexus_list * list);

/**
 * Frees all the contents of the list
 * @param list
 */
void
nexus_list_destroy(struct nexus_list * list);

/**
 * Gets an element at a specific position in the list
 * @param list
 * @param po
 * @return the data
 */
void *
nexus_list_get(struct nexus_list * list, size_t pos);

/**
 * Removes the last element from list and returns to caller. It is the caller's responsibility
 * to free the returned element.
 *
 * @param list
 * @return element, NULL if is empty
 */
void *
nexus_list_pop(struct nexus_list * list);

/**
 * Sets the deallocator function of the list. Called whenever an element is removed
 * @param list
 * @param deallocator
 */
void
nexus_list_set_deallocator(struct nexus_list * list, list_deallocator deallocator);

/**
 * Appends an element to the list
 * @param list
 * @param element
 * @return 0 on success
 */
int
nexus_list_append(struct nexus_list * list, void * element);


/**
 * Creates a new iterator and points to the first element in the list
 * @param list
 * @return struct nexus_list_iterator
 */
struct nexus_list_iterator *
list_iterator_new(struct nexus_list * list);

/**
 * Checks if the iterator points to a valid element
 * @param iter
 * @return bool
 */
bool
list_iterator_is_valid(struct nexus_list_iterator * iter);

/**
 * Returns the element currently pointed by the iterator
 * @param iter
 * @return data
 */
void *
list_iterator_get(struct nexus_list_iterator * iter);

/**
 * Moves the iterator to the next
 * @param iter
 */
void
list_iterator_next(struct nexus_list_iterator * iter);

/**
 * Deletes the item currently pointed by the element. Iterator moves to the
 * next
 * @param iter
 * @return 0 on success
 */
int
list_iterator_del(struct nexus_list_iterator * iter);

/**
 * Frees the allocated iterator
 * @param iter
 */
void
list_iterator_free(struct nexus_list_iterator * iter);
