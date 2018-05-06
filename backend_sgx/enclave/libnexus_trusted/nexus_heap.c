#include <string.h>

#include "nexus_heap.h"


typedef struct __node {
    unsigned int    hole : 1;

    unsigned int    size;

    struct __node * next;

    struct __node * prev;
} node_t;


typedef struct __footer {
    struct __node * header;
} footer_t;



static size_t overhead = sizeof(footer_t) + sizeof(node_t);


static void
add_node(bin_t * bin, node_t * node)
{
    node->next = NULL;
    node->prev = NULL;

    if (bin->head == NULL) {
        bin->head = node;
        return;
    }

    // we need to save next and prev while we iterate
    node_t * current  = bin->head;
    node_t * previous = NULL;
    // iterate until we get the the end of the list or we find a
    // node whose size is
    while (current != NULL && current->size <= node->size) {
        previous = current;
        current  = current->next;
    }

    if (current == NULL) { // we reached the end of the list
        previous->next = node;
        node->prev     = previous;
    } else {
        if (previous != NULL) { // middle of list, connect all links!
            node->next     = current;
            previous->next = node;

            node->prev    = previous;
            current->prev = node;
        } else { // head is the only element
            node->next      = bin->head;
            bin->head->prev = node;
            bin->head       = node;
        }
    }
}

static void
remove_node(bin_t * bin, node_t * node)
{
    if (bin->head == NULL)
        return;
    if (bin->head == node) {
        bin->head = bin->head->next;
        return;
    }

    node_t * temp = bin->head->next;
    while (temp != NULL) {
        if (temp == node) {           // found the node
            if (temp->next == NULL) { // last item
                temp->prev->next = NULL;
            } else { // middle item
                temp->prev->next = temp->next;
                temp->next->prev = temp->prev;
            }
            // we dont worry about deleting the head here because we already checked that
            return;
        }
        temp = temp->next;
    }
}

static node_t *
get_best_fit(bin_t * bin, size_t size)
{
    if (bin->head == NULL)
        return NULL; // empty list!

    node_t * temp = bin->head;

    while (temp != NULL) {
        if (temp->size >= size) {
            return temp; // found a fit!
        }
        temp = temp->next;
    }
    return NULL; // no fit!
}

static footer_t *
get_foot(node_t * node)
{
    return (footer_t *)((char *)node + sizeof(node_t) + node->size);
}

static void
create_foot(node_t * head)
{
    footer_t * foot = get_foot(head);
    foot->header    = head;
}

static size_t
get_bin_index(size_t sz)
{
    size_t index = 0;
    sz           = sz < 4 ? 4 : sz;

    while (sz >>= 1)
        index++;
    index -= 2;

    if (index > MAX_BIN_INDEX)
        index = MAX_BIN_INDEX;
    return index;
}

inline static bin_t *
get_bin_from_index(struct nexus_heap * heap, size_t index)
{
    if (index == MAX_BIN_INDEX) {
	// XXX: maybe fault here
	return NULL;
    }

    return &heap->bins[index];
}

inline static bin_t *
get_bin_from_size(struct nexus_heap * heap, size_t sz)
{
    size_t index = get_bin_index(sz);

    return get_bin_from_index(heap, index);
}

void
nexus_heap_init(struct nexus_heap * heap, uint8_t * start, size_t total_size)
{
    node_t * init_region = (node_t *)start;
    init_region->hole    = 1;
    init_region->size    = total_size - sizeof(node_t) - sizeof(footer_t);

    create_foot(init_region);

    memset(heap, 0, sizeof(struct nexus_heap));

    add_node(get_bin_from_size(heap, init_region->size), init_region);

    heap->size  = total_size;
    heap->start = start;
    heap->end   = start + total_size;
}

void *
nexus_heap_malloc(struct nexus_heap * heap, size_t size)
{
    node_t * found = NULL;

    size_t   index = get_bin_index(size);

    do {
        bin_t * temp = get_bin_from_index(heap, index);

	if (temp == NULL) {
            return NULL;
        }

	index += 1;

        found = get_best_fit(temp, size);
    } while (found == NULL);

    if ((found->size - size) > (overhead + MIN_ALLOC_SIZE)) {
        node_t * split = (node_t *)(((char *)found + overhead) + size);

        split->size    = found->size - size - overhead;

        split->hole    = 1;

        create_foot(split);

        add_node(get_bin_from_size(heap, split->size), split);

        found->size = size;
        create_foot(found);
    }

    found->hole = 0;
    remove_node(get_bin_from_size(heap, found->size), found);

    found->prev = NULL;
    found->next = NULL;
    return (char *)found + sizeof(node_t);
}

void
nexus_heap_free(struct nexus_heap * heap, void * p)
{
    bin_t    * list      = NULL;
    footer_t * new_foot  = NULL;
    footer_t * old_foot  = NULL;

    node_t * head = (node_t *)((char *)p - sizeof(node_t));

    if (head == (node_t *)(uintptr_t)heap->start) {
        head->hole = 1;
        add_node(get_bin_from_size(heap, head->size), head);
        return;
    }

    node_t   * next      = (node_t *)((char *)get_foot(head) + sizeof(footer_t));

    footer_t * f         = (footer_t *)((char *)head - sizeof(footer_t));

    node_t   * prev      = f->header;

    if (prev->hole) {
        list = get_bin_from_size(heap, prev->size);

        remove_node(list, prev);

        prev->size	+= overhead + head->size;

        new_foot         = get_foot(head);

        new_foot->header = prev;

        head = prev;
    }

    if (next->hole) {
        list = get_bin_from_size(heap, next->size);

        remove_node(list, next);

        head->size += overhead + next->size;

        old_foot         = get_foot(next);
        old_foot->header = 0;
        next->size       = 0;
        next->hole       = 0;

        new_foot         = get_foot(head);
        new_foot->header = head;
    }

    head->hole = 1;

    add_node(get_bin_from_size(heap, head->size), head);
}

