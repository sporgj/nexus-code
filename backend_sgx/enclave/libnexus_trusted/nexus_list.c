#include <string.h>

#include "nexus_list.h"
#include "nexus_util.h"

struct list_node {
    void * data;

    struct list_head node;
};

struct nexus_list_iterator {
    struct nexus_list * list;
    struct list_head  * curr;
};

static void
free_list_node(struct nexus_list * list, struct list_node * node)
{
    if (list->attrs.deallocator == NULL) {
        list->attrs.deallocator(node->data);
    }

    list_del(&node->node);

    nexus_free(node);
}

void
nexus_list_init(struct nexus_list * list)
{
    memset(list, 0, sizeof(struct nexus_list));

    INIT_LIST_HEAD(&(list->list));
}

void
nexus_list_destroy(struct nexus_list * list)
{
    struct list_node * node = list_first_entry(&list->list, struct list_node, node);

    while (node != NULL) {
        free_list_node(list, node);
        node = list_first_entry(&list->list, struct list_node, node);
    }
}

void *
nexus_list_get(struct nexus_list * list, size_t pos) {
    struct list_head * head = &list->list;
    struct list_head * curr = &head->next;
    struct list_node * node = NULL;

    if (list_empty(head)) {
        return NULL;
    }

    for (size_t i = 0; i < pos; i++) {
        if (curr == head) {
            return NULL;
        }

        curr = curr->next;
    }

    node = list_entry(curr, struct list_node, node);

    return node->data;
}

void *
nexus_list_pop(struct nexus_list * list)
{
    void * result = NULL;

    struct list_node * last_node = NULL;

    struct list_head * list_head = &list->list;

    if (list_empty(list_head)) {
        return NULL;
    }


    last_node = list_last_entry(list_head, struct list_node, node);
    list_del(&last_node->node);

    result = last_node->data;

    nexus_free(last_node);

    return result;
}

void
nexus_list_set_deallocator(struct nexus_list * list, list_deallocator deallocator)
{
    list->attrs.deallocator = deallocator;
}

int
nexus_list_append(struct nexus_list * list, void * element)
{
    struct list_node * node = NULL;

    node = nexus_malloc(sizeof(struct list_node));

    node->data = element;

    list_add_tail(&list->list, &node->node);

    return 0;
}

struct nexus_list_iterator *
list_iterator_new(struct nexus_list * list)
{
    struct nexus_list_iterator * iter = NULL;

    iter = nexus_malloc(sizeof(struct nexus_list_iterator));

    iter->list = list;
    iter->curr = list->list.next;

    return iter;
}

void *
list_iterator_get(struct nexus_list_iterator * iter)
{
    struct list_node * node = NULL;

    if (iter->curr == &iter->list->list) {
        return NULL;
    }

    node = list_entry(iter->curr, struct list_node, node);

    return node->data;
}

bool
list_iterator_is_valid(struct nexus_list_iterator * iter)
{
    if (iter->curr == &iter->list->list) {
        return false;
    }

    return true;
}

void
list_iterator_next(struct nexus_list_iterator * iter)
{
    if (iter->curr != &iter->list->list) {
        iter->curr = iter->curr->next;
    }
}

int
list_iterator_del(struct nexus_list_iterator * iter)
{
    struct list_node * node = NULL;

    if (iter->curr == &iter->list->list) {
        return -1;
    }

    node = list_entry(iter->curr, struct list_node, node);

    iter->curr = iter->curr->next;

    free_list_node(iter->list, node);

    return 0;
}

void
list_iterator_free(struct nexus_list_iterator * iter)
{
    free(iter);
}
