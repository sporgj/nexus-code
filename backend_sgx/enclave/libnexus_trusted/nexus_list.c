/*
 * Copyright (c) 2007,2008,2009,2010 Mij <mij@bitchx.it>
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

/* SimCList implementation, version 1.5 */

#include <assert.h>

/*
 * how many elems to keep as spare. During a deletion, an element
 * can be saved in a "free-list", not free()d immediately. When
 * latter insertions are performed, spare elems can be used instead
 * of malloc()ing new elems.
 *
 * about this param, some values for appending
 * 10 million elems into an empty list:
 * (#, time[sec], gain[%], gain/no[%])
 * 0    2,164   0,00    0,00    <-- feature disabled
 * 1    1,815   34,9    34,9
 * 2    1,446   71,8    35,9    <-- MAX gain/no
 * 3    1,347   81,7    27,23
 * 5    1,213   95,1    19,02
 * 8    1,064   110,0   13,75
 * 10   1,015   114,9   11,49   <-- MAX gain w/ likely sol
 * 15   1,019   114,5   7,63
 * 25   0,985   117,9   4,72
 * 50   1,088   107,6   2,15
 * 75   1,016   114,8   1,53
 * 100  0,988   117,6   1,18
 * 150  1,022   114,2   0,76
 * 200  0,939   122,5   0,61    <-- MIN time
 */
#ifndef SIMCLIST_MAX_SPARE_ELEMS
#define SIMCLIST_MAX_SPARE_ELEMS 5
#endif

#include "../enclave_internal.h"


/* deletes tmp from list, with care wrt its position (head, tail, middle) */
static int
list_drop_elem(struct nexus_list *  l, struct list_entry_s * tmp, unsigned int pos);

/* set default values for initialized lists */
static int
list_attributes_setdefaults(struct nexus_list *  l);

#ifndef NDEBUG
/* check whether the list internal REPresentation is valid -- Costs O(n) */
static int
list_repOk(const struct nexus_list *  l);

/* check whether the list attribute set is valid -- Costs O(1) */
static int
list_attrOk(const struct nexus_list *  l);
#endif


static void *
list_get_minmax(const struct nexus_list *  l, int versus);

static inline struct list_entry_s *
list_findpos(const struct nexus_list *  l, int posstart);

/* list initialization */
int
list_init(struct nexus_list *  l)
{
    if (l == NULL)
        return -1;

    l->numels = 0;

    /* head/tail sentinels and mid pointer */
    l->head_sentinel       = (struct list_entry_s *)malloc(sizeof(struct list_entry_s));
    l->tail_sentinel       = (struct list_entry_s *)malloc(sizeof(struct list_entry_s));
    l->head_sentinel->next = l->tail_sentinel;
    l->tail_sentinel->prev = l->head_sentinel;
    l->head_sentinel->prev = l->tail_sentinel->next = l->mid = NULL;
    l->head_sentinel->data = l->tail_sentinel->data = NULL;

    /* iteration attributes */
    l->iter_active   = 0;
    l->iter_pos      = 0;
    l->iter_curentry = NULL;

    /* free-list attributes */
    l->spareels
        = (struct list_entry_s **)malloc(SIMCLIST_MAX_SPARE_ELEMS * sizeof(struct list_entry_s *));
    l->spareelsnum = 0;

    list_attributes_setdefaults(l);

    assert(list_repOk(l));
    assert(list_attrOk(l));

    return 0;
}

void
list_destroy(struct nexus_list *  l)
{
    unsigned int i;

    list_clear(l);
    for (i = 0; i < l->spareelsnum; i++) {
        free(l->spareels[i]);
    }
    free(l->spareels);
    free(l->head_sentinel);
    free(l->tail_sentinel);
}

int
list_attributes_setdefaults(struct nexus_list *  l)
{
    l->attrs.comparator = NULL;
    l->attrs.seeker     = NULL;

    /* also free() element data when removing and element from the list */
    l->attrs.meter     = NULL;
    l->attrs.copy_data = 0;

    l->attrs.deallocator = NULL;

    l->attrs.hasher = NULL;

    assert(list_attrOk(l));

    return 0;
}

/* setting list properties */
int
list_attributes_comparator(struct nexus_list *  l, element_comparator comparator_fun)
{
    if (l == NULL)
        return -1;

    l->attrs.comparator = comparator_fun;

    assert(list_attrOk(l));

    return 0;
}

int
list_attributes_seeker(struct nexus_list *  l, element_seeker seeker_fun)
{
    if (l == NULL)
        return -1;

    l->attrs.seeker = seeker_fun;
    assert(list_attrOk(l));

    return 0;
}

int
list_attributes_deallocator(struct nexus_list *  l, element_deallocator dealloc_fun)
{
    if (l == NULL) {
        return -1;
    }

    l->attrs.deallocator = dealloc_fun;
    assert(list_attrOk(l));

    return 0;
}

int
list_attributes_copy(struct nexus_list *  l, element_meter metric_fun, int copy_data)
{
    if (l == NULL || (metric_fun == NULL && copy_data != 0))
        return -1;

    l->attrs.meter     = metric_fun;
    l->attrs.copy_data = copy_data;

    assert(list_attrOk(l));

    return 0;
}

int
list_attributes_hash_computer(struct nexus_list *  l, element_hash_computer hash_computer_fun)
{
    if (l == NULL)
        return -1;

    l->attrs.hasher = hash_computer_fun;
    assert(list_attrOk(l));
    return 0;
}

int
list_append(struct nexus_list *  l, const void * data)
{
    return list_insert_at(l, data, l->numels);
}

int
list_prepend(struct nexus_list *  l, const void * data)
{
    return list_insert_at(l, data, 0);
}

void *
list_fetch(struct nexus_list *  l)
{
    return list_extract_at(l, 0);
}

void *
list_get_at(const struct nexus_list *  l, unsigned int pos)
{
    struct list_entry_s * tmp;

    tmp = list_findpos(l, pos);

    return (tmp != NULL ? tmp->data : NULL);
}

void *
list_get_max(const struct nexus_list *  l)
{
    return list_get_minmax(l, +1);
}

void *
list_get_min(const struct nexus_list *  l)
{
    return list_get_minmax(l, -1);
}

/* REQUIRES {list->numels >= 1}
 * return the min (versus < 0) or max value (v > 0) in l */
static void *
list_get_minmax(const struct nexus_list *  l, int versus)
{
    void *                curminmax;
    struct list_entry_s * s;

    if (l->attrs.comparator == NULL || l->numels == 0)
        return NULL;

    curminmax = l->head_sentinel->next->data;
    for (s = l->head_sentinel->next->next; s != l->tail_sentinel; s = s->next) {
        if (l->attrs.comparator(curminmax, s->data) * versus > 0)
            curminmax = s->data;
    }

    return curminmax;
}

/* set tmp to point to element at index posstart in l */
static inline struct list_entry_s *
list_findpos(const struct nexus_list *  l, int posstart)
{
    struct list_entry_s * ptr;
    float                 x;
    int                   i;

    /* accept 1 slot overflow for fetching head and tail sentinels */
    if (posstart < -1 || posstart > (int)l->numels)
        return NULL;

    x = (float)(posstart + 1) / l->numels;
    if (x <= 0.25) {
        /* first quarter: get to posstart from head */
        for (i = -1, ptr = l->head_sentinel; i < posstart; ptr = ptr->next, i++)
            ;
    } else if (x < 0.5) {
        /* second quarter: get to posstart from mid */
        for (i = (l->numels - 1) / 2, ptr = l->mid; i > posstart; ptr = ptr->prev, i--)
            ;
    } else if (x <= 0.75) {
        /* third quarter: get to posstart from mid */
        for (i = (l->numels - 1) / 2, ptr = l->mid; i < posstart; ptr = ptr->next, i++)
            ;
    } else {
        /* fourth quarter: get to posstart from tail */
        for (i = l->numels, ptr = l->tail_sentinel; i > posstart; ptr = ptr->prev, i--)
            ;
    }

    return ptr;
}

void *
list_extract_at(struct nexus_list *  l, unsigned int pos)
{
    struct list_entry_s * tmp;
    void *                data;

    if (l->iter_active || pos >= l->numels)
        return NULL;

    tmp  = list_findpos(l, pos);
    data = tmp->data;

    tmp->data = NULL; /* save data from list_drop_elem() free() */
    list_drop_elem(l, tmp, pos);
    l->numels--;

    assert(list_repOk(l));

    return data;
}

int
list_insert_at(struct nexus_list *  l, const void * data, unsigned int pos)
{
    struct list_entry_s *lent, *succ, *prec;

    if (l->iter_active || pos > l->numels)
        return -1;

    /* this code optimizes malloc() with a free-list */
    if (l->spareelsnum > 0) {
        lent = l->spareels[l->spareelsnum - 1];
        l->spareelsnum--;
    } else {
        lent = (struct list_entry_s *)malloc(sizeof(struct list_entry_s));
        if (lent == NULL)
            return -1;
    }

    if (l->attrs.copy_data) {
        /* make room for user' data (has to be copied) */
        size_t datalen = l->attrs.meter(data);
        lent->data     = (struct list_entry_s *)malloc(datalen);
        memcpy(lent->data, data, datalen);
    } else {
        lent->data = (void *)data;
    }

    /* actually append element */
    prec = list_findpos(l, pos - 1);
    succ = prec->next;

    prec->next = lent;
    lent->prev = prec;
    lent->next = succ;
    succ->prev = lent;

    l->numels++;

    /* fix mid pointer */
    if (l->numels == 1) { /* first element, set pointer */
        l->mid = lent;
    } else if (l->numels % 2) { /* now odd */
        if (pos >= (l->numels - 1) / 2)
            l->mid = l->mid->next;
    } else { /* now even */
        if (pos <= (l->numels - 1) / 2)
            l->mid = l->mid->prev;
    }

    assert(list_repOk(l));

    return 1;
}

int
list_delete(struct nexus_list *  l, const void * data)
{
    int pos, r;

    pos = list_locate(l, data);
    if (pos < 0)
        return -1;

    r = list_delete_at(l, pos);
    if (r < 0)
        return -1;

    assert(list_repOk(l));

    return 0;
}

int
list_delete_at(struct nexus_list *  l, unsigned int pos)
{
    struct list_entry_s * delendo;

    if (l->iter_active || pos >= l->numels)
        return -1;

    delendo = list_findpos(l, pos);

    list_drop_elem(l, delendo, pos);

    l->numels--;

    assert(list_repOk(l));

    return 0;
}

int
list_delete_range(struct nexus_list *  l, unsigned int posstart, unsigned int posend)
{
    struct list_entry_s *lastvalid, *tmp, *tmp2;
    unsigned int         i;
    int                  movedx;
    unsigned int         numdel, midposafter;

    if (l->iter_active || posend < posstart || posend >= l->numels)
        return -1;

    tmp       = list_findpos(l, posstart); /* first el to be deleted */
    lastvalid = tmp->prev;                 /* last valid element */

    numdel      = posend - posstart + 1;
    midposafter = (l->numels - 1 - numdel) / 2;

    midposafter = midposafter < posstart ? midposafter : midposafter + numdel;
    movedx      = midposafter - (l->numels - 1) / 2;

    if (movedx > 0) { /* move right */
        for (i = 0; i < (unsigned int)movedx; l->mid = l->mid->next, i++)
            ;
    } else { /* move left */
        movedx = -movedx;
        for (i = 0; i < (unsigned int)movedx; l->mid = l->mid->prev, i++)
            ;
    }

    assert(posstart == 0 || lastvalid != l->head_sentinel);
    i = posstart;
    if (l->attrs.copy_data) {
        /* also free element data */
        for (; i <= posend; i++) {
            tmp2 = tmp;
            tmp  = tmp->next;
            if (tmp2->data != NULL)
                free(tmp2->data);
            if (l->spareelsnum < SIMCLIST_MAX_SPARE_ELEMS) {
                l->spareels[l->spareelsnum++] = tmp2;
            } else {
                free(tmp2);
            }
        }
    } else {
        /* only free containers */
        for (; i <= posend; i++) {
            tmp2 = tmp;
            tmp  = tmp->next;

            if (l->attrs.deallocator != NULL) {
                l->attrs.deallocator(tmp2->data);
            }

            if (l->spareelsnum < SIMCLIST_MAX_SPARE_ELEMS) {
                l->spareels[l->spareelsnum++] = tmp2;
            } else {
                free(tmp2);
            }
        }
    }
    assert(i == posend + 1 && (posend != l->numels || tmp == l->tail_sentinel));

    lastvalid->next = tmp;
    tmp->prev       = lastvalid;

    l->numels -= posend - posstart + 1;

    assert(list_repOk(l));

    return 0;
}

int
list_clear(struct nexus_list *  l)
{
    struct list_entry_s * s;

    if (l->iter_active)
        return -1;

    if (l->attrs.copy_data) { /* also free user data */
        /* spare a loop conditional with two loops: spareing elems and freeing elems */
        for (s = l->head_sentinel->next;
             l->spareelsnum < SIMCLIST_MAX_SPARE_ELEMS && s != l->tail_sentinel;
             s = s->next) {
            /* move elements as spares as long as there is room */
            if (s->data != NULL)
                free(s->data);
            l->spareels[l->spareelsnum++] = s;
        }
        while (s != l->tail_sentinel) {
            /* free the remaining elems */
            if (s->data != NULL)
                free(s->data);
            s = s->next;
            free(s->prev);
        }
        l->head_sentinel->next = l->tail_sentinel;
        l->tail_sentinel->prev = l->head_sentinel;
    } else { /* only free element containers */
        /* spare a loop conditional with two loops: spareing elems and freeing elems */
        for (s = l->head_sentinel->next;
             l->spareelsnum < SIMCLIST_MAX_SPARE_ELEMS && s != l->tail_sentinel;
             s = s->next) {
            /* move elements as spares as long as there is room */
            if (l->attrs.deallocator != NULL) {
                l->attrs.deallocator(s->data);
            }

            l->spareels[l->spareelsnum++] = s;
        }
        while (s != l->tail_sentinel) {
            /* free the remaining elems */
            if (l->attrs.deallocator != NULL) {
                l->attrs.deallocator(s->data);
            }

            s = s->next;
            free(s->prev);
        }
        l->head_sentinel->next = l->tail_sentinel;
        l->tail_sentinel->prev = l->head_sentinel;
    }
    l->numels = 0;
    l->mid    = NULL;

    assert(list_repOk(l));

    return 0;
}

unsigned int
list_size(const struct nexus_list *  l)
{
    return l->numels;
}

int
list_empty(const struct nexus_list *  l)
{
    return (l->numels == 0);
}

int
list_locate(const struct nexus_list *  l, const void * data)
{
    struct list_entry_s * el;
    int                   pos = 0;

    if (l->attrs.comparator != NULL) {
        /* use comparator */
        for (el = l->head_sentinel->next; el != l->tail_sentinel; el = el->next, pos++) {
            if (l->attrs.comparator(data, el->data) == 0)
                break;
        }
    } else {
        /* compare references */
        for (el = l->head_sentinel->next; el != l->tail_sentinel; el = el->next, pos++) {
            if (el->data == data)
                break;
        }
    }
    if (el == l->tail_sentinel)
        return -1;

    return pos;
}

void *
list_seek(struct nexus_list *  l, const void * indicator)
{
    const struct list_entry_s * iter;

    if (l->attrs.seeker == NULL)
        return NULL;

    for (iter = l->head_sentinel->next; iter != l->tail_sentinel; iter = iter->next) {
        if (l->attrs.seeker(iter->data, indicator) != 0)
            return iter->data;
    }

    return NULL;
}

int
list_contains(const struct nexus_list *  l, const void * data)
{
    return (list_locate(l, data) >= 0);
}

int
list_concat(const struct nexus_list * l1, const struct nexus_list * l2, struct nexus_list *  dest)
{
    struct list_entry_s *el, *srcel;
    unsigned int         cnt;
    int                  err;

    if (l1 == NULL || l2 == NULL || dest == NULL || l1 == dest || l2 == dest)
        return -1;

    list_init(dest);

    dest->numels = l1->numels + l2->numels;
    if (dest->numels == 0)
        return 0;

    /* copy list1 */
    srcel = l1->head_sentinel->next;
    el    = dest->head_sentinel;
    while (srcel != l1->tail_sentinel) {
        el->next       = (struct list_entry_s *)malloc(sizeof(struct list_entry_s));
        el->next->prev = el;
        el             = el->next;
        el->data       = srcel->data;
        srcel          = srcel->next;
    }
    dest->mid = el; /* approximate position (adjust later) */
    /* copy list 2 */
    srcel = l2->head_sentinel->next;
    while (srcel != l2->tail_sentinel) {
        el->next       = (struct list_entry_s *)malloc(sizeof(struct list_entry_s));
        el->next->prev = el;
        el             = el->next;
        el->data       = srcel->data;
        srcel          = srcel->next;
    }
    el->next                  = dest->tail_sentinel;
    dest->tail_sentinel->prev = el;

    /* fix mid pointer */
    err = l2->numels - l1->numels;
    if ((err + 1) / 2 > 0) { /* correct pos RIGHT (err-1)/2 moves */
        err = (err + 1) / 2;
        for (cnt = 0; cnt < (unsigned int)err; cnt++)
            dest->mid = dest->mid->next;
    } else if (err / 2 < 0) { /* correct pos LEFT (err/2)-1 moves */
        err = -err / 2;
        for (cnt = 0; cnt < (unsigned int)err; cnt++)
            dest->mid = dest->mid->prev;
    }

    assert(!(list_repOk(l1) && list_repOk(l2)) || list_repOk(dest));

    return 0;
}

int
list_iterator_start(struct nexus_list *  l)
{
    if (l->iter_active)
        return 0;
    l->iter_pos      = 0;
    l->iter_active   = 1;
    l->iter_curentry = l->head_sentinel->next;
    return 1;
}

void *
list_iterator_next(struct nexus_list *  l)
{
    void * toret;

    if (!l->iter_active)
        return NULL;

    toret            = l->iter_curentry->data;
    l->iter_curentry = l->iter_curentry->next;
    l->iter_pos++;

    return toret;
}

int
list_iterator_hasnext(const struct nexus_list *  l)
{
    if (!l->iter_active)
        return 0;
    return (l->iter_pos < l->numels);
}

int
list_iterator_stop(struct nexus_list *  l)
{
    if (!l->iter_active)
        return 0;
    l->iter_pos    = 0;
    l->iter_active = 0;
    return 1;
}

int
list_hash(const struct nexus_list *  l, list_hash_t *  hash)
{
    struct list_entry_s * x;
    list_hash_t           tmphash;

    assert(hash != NULL);

    tmphash = l->numels * 2 + 100;
    if (l->attrs.hasher == NULL) {
#ifdef SIMCLIST_ALLOW_LOCATIONBASED_HASHES
/* ENABLE WITH CARE !! */
#warning                                                                                           \
    "Memlocation-based hash is consistent only for testing modification in the same program run."
        int i;

        /* only use element references */
        for (x = l->head_sentinel->next; x != l->tail_sentinel; x = x->next) {
            for (i = 0; i < sizeof(x->data); i++) {
                tmphash += (tmphash ^ (uintptr_t)x->data);
            }
            tmphash += tmphash % l->numels;
        }
#else
        return -1;
#endif
    } else {
        /* hash each element with the user-given function */
        for (x = l->head_sentinel->next; x != l->tail_sentinel; x = x->next) {
            tmphash += tmphash ^ l->attrs.hasher(x->data);
            tmphash += *hash % l->numels;
        }
    }

    *hash = tmphash;

    return 0;
}

static int
list_drop_elem(struct nexus_list *  l, struct list_entry_s * tmp, unsigned int pos)
{
    if (tmp == NULL)
        return -1;

    /* fix mid pointer. This is wrt the PRE situation */
    if (l->numels % 2) { /* now odd */
        /* sort out the base case by hand */
        if (l->numels == 1)
            l->mid = NULL;
        else if (pos >= l->numels / 2)
            l->mid = l->mid->prev;
    } else { /* now even */
        if (pos < l->numels / 2)
            l->mid = l->mid->next;
    }

    tmp->prev->next = tmp->next;
    tmp->next->prev = tmp->prev;

    /* free what's to be freed */
    if (l->attrs.copy_data && tmp->data != NULL)
        free(tmp->data);

    if (l->spareelsnum < SIMCLIST_MAX_SPARE_ELEMS) {
        l->spareels[l->spareelsnum++] = tmp;
    } else {
        free(tmp);
    }

    return 0;
}

#ifndef NDEBUG
static int
list_repOk(const struct nexus_list *  l)
{
    int                   ok, i;
    struct list_entry_s * s;

    ok = (l != NULL)
         && (
                /* head/tail checks */
                (l->head_sentinel != NULL && l->tail_sentinel != NULL)
                && (l->head_sentinel != l->tail_sentinel)
                && (l->head_sentinel->prev == NULL && l->tail_sentinel->next == NULL)
                &&
                /* empty list */
                (l->numels > 0 || (l->mid == NULL && l->head_sentinel->next == l->tail_sentinel
                                   && l->tail_sentinel->prev == l->head_sentinel))
                &&
                /* spare elements checks */
                l->spareelsnum <= SIMCLIST_MAX_SPARE_ELEMS);

    if (!ok)
        return 0;

    if (l->numels >= 1) {
        /* correct referencing */
        for (i = -1, s = l->head_sentinel; i < (int)(l->numels - 1) / 2 && s->next != NULL;
             i++, s    = s->next) {
            if (s->next->prev != s)
                break;
        }
        ok = (i == (int)(l->numels - 1) / 2 && l->mid == s);
        if (!ok)
            return 0;
        for (; s->next != NULL; i++, s = s->next) {
            if (s->next->prev != s)
                break;
        }
        ok = (i == (int)l->numels && s == l->tail_sentinel);
    }

    return ok;
}

static int
list_attrOk(const struct nexus_list *  l)
{
    int ok;

    ok = (l->attrs.copy_data == 0 || l->attrs.meter != NULL);
    return ok;
}

#endif
