/*
 * Copyright (c) 2007,2008 Mij <mij@bitchx.it>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * SimCList library. See http://mij.oltrelinux.com/devel/simclist
 */

/*
 * Removed functions and includes for SGX compatibility
 * @author 2018 - Judicael Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

typedef uint32_t list_hash_t;

/**
 * a comparator of elements.
 *
 * A comparator of elements is a function that:
 *      -# receives two references to elements a and b
 *      -# returns {<0, 0, >0} if (a > b), (a == b), (a < b) respectively
 *
 * It is responsability of the function to handle possible NULL values.
 */
typedef int (*element_comparator)(const void * a, const void * b);

/**
 * a seeker of elements.
 *
 * An element seeker is a function that:
 *      -# receives a reference to an element el
 *      -# receives a reference to some indicator data
 *      -# returns non-0 if the element matches the indicator, 0 otherwise
 *
 * It is responsability of the function to handle possible NULL values in any
 * argument.
 */
typedef int (*element_seeker)(const void * el, const void * indicator);

/**
 * an element lenght meter.
 *
 * An element meter is a function that:
 *      -# receives the reference to an element el
 *      -# returns its size in bytes
 *
 * It is responsability of the function to handle possible NULL values.
 */
typedef size_t (*element_meter)(const void * el);

/**
 * an element deallocator. @author Judicael
 *
 * An element freer is a function that:
 *      - receives the reference to an element
 *      - frees the allocated buffer
 *
 * Its responsibility is to free elements added to the list. Must handle NULL
 */
typedef void (*element_deallocator)(void * el);

/**
 * a function computing the hash of elements.
 *
 * An hash computing function is a function that:
 *      -# receives the reference to an element el
 *      -# returns a hash value for el
 *
 * It is responsability of the function to handle possible NULL values.
 */
typedef list_hash_t (*element_hash_computer)(const void * el);

/* [private-use] list entry -- olds actual user datum */
struct list_entry_s {
    void * data;

    /* doubly-linked list service references */
    struct list_entry_s * next;
    struct list_entry_s * prev;
};

/* [private-use] list attributes */
struct list_attributes_s {
    /* user-set routine for comparing list elements */
    element_comparator comparator;
    /* user-set routing for seeking elements */
    element_seeker seeker;
    /* user-set routine for determining the length of an element */
    element_meter meter;
    /* user-set routine for freeing an element */
    element_deallocator deallocator;

    int copy_data;

    /* user-set routine for computing the hash of an element */
    element_hash_computer hasher;
};

/** list object */
struct nexus_list {
    struct list_entry_s * head_sentinel;
    struct list_entry_s * tail_sentinel;
    struct list_entry_s * mid;

    unsigned int numels;

    /* array of spare elements */
    struct list_entry_s ** spareels;
    unsigned int           spareelsnum;

#ifdef SIMCLIST_WITH_THREADS
    /* how many threads are currently running */
    unsigned int threadcount;
#endif

    /* service variables for list iteration */
    int                   iter_active;
    unsigned int          iter_pos;
    struct list_entry_s * iter_curentry;

    /* list attributes */
    struct list_attributes_s attrs;
};

/**
 * initialize a list object for use.
 *
 * @param l     must point to a user-provided memory location
 * @return      0 for success. -1 for failure
 */
int
list_init(struct nexus_list *  l);

/**
 * completely remove the list from memory.
 *
 * This function is the inverse of list_init(). It is meant to be called when
 * the list is no longer going to be used. Elements and possible memory taken
 * for internal use are freed.
 *
 * @param l     list to destroy
 */
void
list_destroy(struct nexus_list *  l);

/**
 * set the comparator function for list elements.
 *
 * Comparator functions are used for searching and sorting. If NULL is passed
 * as reference to the function, the comparator is disabled.
 *
 * @param l     list to operate
 * @param comparator_fun    pointer to the actual comparator function
 * @return      0 if the attribute was successfully set; -1 otherwise
 *
 * @see element_comparator()
 */
int
list_attributes_comparator(struct nexus_list *  l, element_comparator comparator_fun);

/**
 * set a seeker function for list elements.
 *
 * Seeker functions are used for finding elements. If NULL is passed as reference
 * to the function, the seeker is disabled.
 *
 * @param l     list to operate
 * @param seeker_fun    pointer to the actual seeker function
 * @return      0 if the attribute was successfully set; -1 otherwise
 *
 * @see element_seeker()
 */
int
list_attributes_seeker(struct nexus_list *  l, element_seeker seeker_fun);


/**
 * Set the deallocator function for list elements
 *
 * Deallocators are used for freeing elements.
 *
 * @param l list to operate
 * @param dealloc_fun is the deallocator function
 *
 * return 0 if the attribute was successfully set
 */
int
list_attributes_deallocator(struct nexus_list *  l, element_deallocator dealloc_fun);

/**
 * require to free element data when list entry is removed (default: don't free).
 *
 * [ advanced preference ]
 *
 * By default, when an element is removed from the list, it disappears from
 * the list by its actual data is not free()d. With this option, every
 * deletion causes element data to be freed.
 *
 * It is responsability of this function to correctly handle NULL values, if
 * NULL elements are inserted into the list.
 *
 * @param l             list to operate
 * @param metric_fun    pointer to the actual metric function
 * @param copy_data     0: do not free element data (default); non-0: do free
 * @return          0 if the attribute was successfully set; -1 otherwise
 *
 * @see element_meter()
 * @see list_meter_int8_t()
 * @see list_meter_int16_t()
 * @see list_meter_int32_t()
 * @see list_meter_int64_t()
 * @see list_meter_uint8_t()
 * @see list_meter_uint16_t()
 * @see list_meter_uint32_t()
 * @see list_meter_uint64_t()
 * @see list_meter_float()
 * @see list_meter_double()
 * @see list_meter_string()
 */
int
list_attributes_copy(struct nexus_list *  l, element_meter metric_fun, int copy_data);

/**
 * append data at the end of the list.
 *
 * This function is useful for adding elements with a FIFO/queue policy.
 *
 * @param l     list to operate
 * @param data  pointer to user data to append
 *
 * @return      1 for success. < 0 for failure
 */
int
list_append(struct nexus_list *  l, const void * data);

/**
 * insert data in the head of the list.
 *
 * This function is useful for adding elements with a LIFO/Stack policy.
 *
 * @param l     list to operate
 * @param data  pointer to user data to append
 *
 * @return      1 for success. < 0 for failure
 */
int
list_prepend(struct nexus_list *  l, const void *  data);

/**
 * extract the element in the top of the list.
 *
 * This function is for using a list with a FIFO/queue policy.
 *
 * @param l     list to operate
 * @return      reference to user datum, or NULL on errors
 */
void *
list_fetch(struct nexus_list *  l);

/**
 * retrieve an element at a given position.
 *
 * @param l     list to operate
 * @param pos   [0,size-1] position index of the element wanted
 * @return      reference to user datum, or NULL on errors
 */
void *
list_get_at(const struct nexus_list *  l, unsigned int pos);

/**
 * return the maximum element of the list.
 *
 * @warning Requires a comparator function to be set for the list.
 *
 * Returns the maximum element with respect to the comparator function output.
 *
 * @see list_attributes_comparator()
 *
 * @param l     list to operate
 * @return      the reference to the element, or NULL
 */
void *
list_get_max(const struct nexus_list *  l);

/**
 * return the minimum element of the list.
 *
 * @warning Requires a comparator function to be set for the list.
 *
 * Returns the minimum element with respect to the comparator function output.
 *
 * @see list_attributes_comparator()
 *
 * @param l     list to operate
 * @return      the reference to the element, or NULL
 */
void *
list_get_min(const struct nexus_list *  l);

/**
 * retrieve and remove from list an element at a given position.
 *
 * @param l     list to operate
 * @param pos   [0,size-1] position index of the element wanted
 * @return      reference to user datum, or NULL on errors
 */
void *
list_extract_at(struct nexus_list *  l, unsigned int pos);

/**
 * insert an element at a given position.
 *
 * @param l     list to operate
 * @param data  reference to data to be inserted
 * @param pos   [0,size-1] position index to insert the element at
 * @return      positive value on success. Negative on failure
 */
int
list_insert_at(struct nexus_list *  l, const void * data, unsigned int pos);

/**
 * expunge the first found given element from the list.
 *
 * Inspects the given list looking for the given element; if the element
 * is found, it is removed. Only the first occurence is removed.
 * If a comparator function was not set, elements are compared by reference.
 * Otherwise, the comparator is used to match the element.
 *
 * @param l     list to operate
 * @param data  reference of the element to search for
 * @return      0 on success. Negative value on failure
 *
 * @see list_attributes_comparator()
 * @see list_delete_at()
 */
int
list_delete(struct nexus_list *  l, const void * data);

/**
 * expunge an element at a given position from the list.
 *
 * @param l     list to operate
 * @param pos   [0,size-1] position index of the element to be deleted
 * @return      0 on success. Negative value on failure
 */
int
list_delete_at(struct nexus_list *  l, unsigned int pos);

/**
 * expunge an array of elements from the list, given their position range.
 *
 * @param l     list to operate
 * @param posstart  [0,size-1] position index of the first element to be deleted
 * @param posend    [posstart,size-1] position of the last element to be deleted
 * @return      the number of elements successfully removed
 */
int
list_delete_range(struct nexus_list *  l, unsigned int posstart, unsigned int posend);

/**
 * clear all the elements off of the list.
 *
 * The element datums will not be freed.
 *
 * @see list_delete_range()
 * @see list_size()
 *
 * @param l     list to operate
 * @return      the number of elements in the list before cleaning
 */
int
list_clear(struct nexus_list *  l);

/**
 * inspect the number of elements in the list.
 *
 * @param l     list to operate
 * @return      number of elements currently held by the list
 */
unsigned int
list_size(const struct nexus_list *  l);

/**
 * inspect whether the list is empty.
 *
 * @param l     list to operate
 * @return      0 iff the list is not empty
 *
 * @see list_size()
 */
int
list_empty(const struct nexus_list *  l);

/**
 * find the position of an element in a list.
 *
 * @warning Requires a comparator function to be set for the list.
 *
 * Inspects the given list looking for the given element; if the element
 * is found, its position into the list is returned.
 * Elements are inspected comparing references if a comparator has not been
 * set. Otherwise, the comparator is used to find the element.
 *
 * @param l     list to operate
 * @param data  reference of the element to search for
 * @return      position of element in the list, or <0 if not found
 *
 * @see list_attributes_comparator()
 * @see list_get_at()
 */
int
list_locate(const struct nexus_list *  l, const void * data);

/**
 * returns an element given an indicator.
 *
 * @warning Requires a seeker function to be set for the list.
 *
 * Inspect the given list looking with the seeker if an element matches
 * an indicator. If such element is found, the reference to the element
 * is returned.
 *
 * @param l     list to operate
 * @param indicator indicator data to pass to the seeker along with elements
 * @return      reference to the element accepted by the seeker, or NULL if none found
 */
void *
list_seek(struct nexus_list *  l, const void * indicator);

/**
 * inspect whether some data is member of the list.
 *
 * @warning Requires a comparator function to be set for the list.
 *
 * By default, a per-reference comparison is accomplished. That is,
 * the data is in list if any element of the list points to the same
 * location of data.
 * A "semantic" comparison is accomplished, otherwise, if a comparator
 * function has been set previously, with list_attributes_comparator();
 * in which case, the given data reference is believed to be in list iff
 * comparator_fun(elementdata, userdata) == 0 for any element in the list.
 *
 * @param l     list to operate
 * @param data  reference to the data to search
 * @return      0 iff the list does not contain data as an element
 *
 * @see list_attributes_comparator()
 */
int
list_contains(const struct nexus_list *  l, const void * data);

/**
 * concatenate two lists
 *
 * Concatenates one list with another, and stores the result into a
 * user-provided list object, which must be different from both the
 * lists to concatenate. Attributes from the original lists are not
 * cloned.
 * The destination list referred is threated as virgin room: if it
 * is an existing list containing elements, memory leaks will happen.
 * It is OK to specify the same list twice as source, for "doubling"
 * it in the destination.
 *
 * @param l1    base list
 * @param l2    list to append to the base
 * @param dest  reference to the destination list
 * @return      0 for success, -1 for errors
 */
int
list_concat(const struct nexus_list * l1, const struct nexus_list * l2, struct nexus_list *  dest);

/**
 * sort list elements.
 *
 * @warning Requires a comparator function to be set for the list.
 *
 * Sorts the list in ascending or descending order as specified by the versus
 * flag. The algorithm chooses autonomously what algorithm is best suited for
 * sorting the list wrt its current status.
 *
 * @param l     list to operate
 * @param versus positive: order small to big; negative: order big to small
 * @return      0: sorting went OK      non-0: errors happened
 *
 * @see list_attributes_comparator()
 */
int
list_sort(struct nexus_list *  l, int versus);

/**
 * start an iteration session.
 *
 * This function prepares the list to be iterated.
 *
 * @param l     list to operate
 * @return 		0 if the list cannot be currently iterated. >0 otherwise
 *
 * @see list_iterator_stop()
 */
int
list_iterator_start(struct nexus_list *  l);

/**
 * return the next element in the iteration session.
 *
 * @param l     list to operate
 * @return		element datum, or NULL on errors
 */
void *
list_iterator_next(struct nexus_list *  l);

/**
 * inspect whether more elements are available in the iteration session.
 *
 * @param l     list to operate
 * @return      0 iff no more elements are available.
 */
int
list_iterator_hasnext(const struct nexus_list *  l);

/**
 * end an iteration session.
 *
 * @param l     list to operate
 * @return      0 iff the iteration session cannot be stopped
 */
int
list_iterator_stop(struct nexus_list *  l);

/**
 * return the hash of the current status of the list.
 *
 * @param l     list to operate
 * @param hash  where the resulting hash is put
 *
 * @return      0 for success; <0 for failure
 */
int
list_hash(const struct nexus_list *  l, list_hash_t *  hash);

#ifdef __cplusplus
}
#endif
