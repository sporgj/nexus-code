#include "uc_dirnode.h"
#include "uc_filebox.h"
#include "uc_utils.h"
#include "uc_vfs.h"

#include "third/log.h"
#include "third/queue.h"

static void
d_free(dentry_t * dentry)
{
    if (dentry) {
        sdsfree(dentry->key.name);
        free(dentry);
    }
}

static dentry_t *
d_alloc(dentry_t * parent, const shadow_t * shdw, const char * name)
{
    dentry_t * dentry = (dentry_t *)calloc(1, sizeof(dentry_t));
    if (dentry == NULL) {
        log_fatal("allocation error on new dentry_t");
        return NULL;
    }

    dentry->count = 1;
    dentry->negative = true;
    dentry->key.parent = parent;
    dentry->key.name = sdsnew(name);
    dentry->key.len = strlen(name);
    dentry->tree = parent ? parent->tree : NULL;
    memcpy(&dentry->shdw_name, shdw, sizeof(shadow_t));

    TAILQ_INIT(&dentry->subdirs);

    return dentry;
}

struct dentry_tree *
d_alloc_root(shadow_t * root_shdw, sds watch_path, sds afsx_path)
{
    int err = -1;
    sds root_path;
    struct dentry_tree * tree = NULL;
    if ((tree = calloc(1, sizeof(struct dentry_tree))) == NULL) {
        log_fatal("allocation failed");
        return NULL;
    }

    /* setup the root dentry */
    tree->root_dentry = d_alloc(NULL, root_shdw, "");
    tree->root_dentry->is_root = true;
    tree->root_dentry->tree = tree;

    tree->afsx_path = afsx_path;
    tree->watch_path = watch_path;

    return tree;
}

dentry_t *
d_instantiate(dentry_t * dentry, metadata_t * mcache)
{
    dentry_list_entry_t * dentry_entry;
    dentry_entry = (dentry_list_entry_t *)malloc(sizeof(dentry_list_entry_t));
    if (dentry_entry == NULL) {
        log_fatal("allocation error");
        return NULL;
    }

    dentry_entry->dentry = dentry;

    TAILQ_INSERT_HEAD(&mcache->aliases, dentry_entry, next_entry);
    dentry->metadata = mcache;
    dentry->negative = false;
}

static int
d_add(dentry_t * parent, dentry_t * child)
{
    dentry_item_t * d_item = (dentry_item_t *)malloc(sizeof(dentry_item_t));
    if (d_item == NULL) {
        log_fatal("allocation error");
        return -1;
    }

    d_item->dentry = child;

    TAILQ_INSERT_HEAD(&parent->subdirs, d_item, next_entry);
    return 0;
}

/* must call d_put when finished */
static dentry_t *
__d_lookup(dentry_t * parent, const char * name, dentry_item_t ** d_item)
{
    int len = strlen(name);
    dentry_item_t * item;
    dentry_t * dentry;

    TAILQ_FOREACH(item, &parent->subdirs, next_entry)
    {
        dentry = item->dentry;
        if (len == dentry->key.len && !memcmp(dentry->key.name, name, len)) {
            if (d_item) {
                *d_item = item;
            }

            return dentry;
        }
    }

    return NULL;
}

inline static dentry_t *
d_lookup(dentry_t * parent, const char * name)
{
    return __d_lookup(parent, name, NULL);
}

void
d_get(dentry_t * dentry)
{
    if (!dentry) {
        return;
    }

    atomic_fetch_add(&dentry->count, 1);
}

void
d_put(dentry_t * dentry)
{
    if (!dentry) {
        return;
    }

    atomic_fetch_sub(&dentry->count, 1);
    if (dentry->count < 0) {
        log_warn("negative ref count dentry(%p)=%d", dentry, dentry->count);
    }
}

static void
d_prune(dentry_item_t * dentry_item)
{
    dentry_t * dentry = dentry_item->dentry;
    dentry_item_t * child_item;

    while (!TAILQ_EMPTY(&dentry->subdirs)) {
        d_prune((child_item = TAILQ_FIRST(&dentry->subdirs)));
        TAILQ_REMOVE(&dentry->subdirs, child_item, next_entry);
    }

    /* remove it from the metadata list */
    if (dentry->metadata) {
        dentry_list_head_t * aliases = &dentry->metadata->aliases;
        struct dentry_list_entry * var;

        TAILQ_FOREACH(var, aliases, next_entry)
        {
            if (var->dentry == dentry) {
                break;
            }
        }

        TAILQ_REMOVE(aliases, var, next_entry);
        free(var);
        metadata_prune(dentry->metadata);
    }

    d_free(dentry);
}

void
d_remove(dentry_t * parent, const char * name)
{
    dentry_item_t * d_item;

    if ((__d_lookup(parent, name, &d_item))) {

        /* remove from the parent list and free the dentry */
        TAILQ_REMOVE(&parent->subdirs, d_item, next_entry);
        d_prune(d_item);
    }
}

static dentry_t *
path_walk(dentry_t * parent, path_builder_t * path_build, char * path_cstr)
{
    int jrnl;
    dentry_t * dentry;
    ucafs_entry_type atype;
    char *nch, *pch;
    const link_info_t * link_info;
    const shadow_t * shdw;
    uc_dirnode_t * dn = NULL;
    struct path_element * path_elmt;

    /* start tokenizing */
    nch = strtok_r(path_cstr, "/", &pch);

    while (nch) {
        link_info = NULL;

        /* 1 - check for . and .. */
        if (nch[0] == '.') {
            if (nch[1] == '\0') {
                // then let's skip to the next one
                goto next1;
            }

            if (nch[1] == '.' && nch[2] == '\0') {
                // move up by one parent_dentry and go to the next
                dentry = (struct uc_dentry *)parent->key.parent;
                if (dentry == NULL) {
                    break;
                }

                path_elmt = TAILQ_LAST(path_build, path_builder);
                TAILQ_REMOVE(path_build, path_elmt, next_entry);
                free(path_elmt);
                goto next;
            }
        }

        /* 2 - check if the dentry has the entry */
        if ((dentry = d_lookup(parent, nch))) {
            goto next;
        }

        /* 3 - if the entry doesn't exist, we need to do a real lookup */
        if ((dn = metadata_get_dirnode(path_build, parent)) == NULL) {
            break;
        }

        shdw = dirnode_traverse(dn, nch, UC_ANY, &atype, &jrnl, &link_info);
        if (shdw == NULL || atype == UC_FILE) {
            break;
        }

        /* 4 - if we are a link, recursion... */
        if (atype == UC_LINK) {
            /* get the link and recursively traverse */
            char * link_cstr = strdup(link_info->target_link);
            dentry = path_walk(parent, path_build, link_cstr);
            free(link_cstr);

            if (dentry) {
                goto next;
            }
        }

        /* 5 - finally, create our new item */
        dentry = d_alloc(parent, shdw, nch);
        d_add(parent, dentry);
        dentry->negative = (jrnl != JRNL_NOOP);

    next:
        /* 5 - add it to the parent list */
        if (!dentry->is_root) {
            path_elmt
                = (struct path_element *)malloc(sizeof(struct path_element));
            if (path_elmt == NULL) {
                log_fatal("allocation error");
                return NULL;
            }
        }

        parent = dentry;
    next1:
        nch = strtok_r(NULL, "/", &pch);
    }

out:
    /* if we don't consume the string to the last component, return NULL */
    return nch ? NULL : dentry;
}

static void
free_path_builder(path_builder_t * path_build)
{
    struct path_element * path_elmt;

    while ((path_elmt = TAILQ_FIRST(path_build))) {
        TAILQ_REMOVE(path_build, path_elmt, next_entry);
        free(path_elmt);
    }
}

/**
 * Performs a lookup of the corresponding path
 * @param path is the full file path
 * @param dirpath just the parent or the child directory
 * return the corresponding uc_dentry, else NULL if not found
 */
static inline uc_dirnode_t *
_dcache_lookup(struct dentry_tree * tree,
               path_builder_t * path_build,
               struct uc_dentry ** pp_dentry,
               const char * path,
               lookup_flags_t flags)
{
    struct uc_dentry * dentry;
    uc_dirnode_t * dirnode = NULL;
    sds relpath;
    bool is_parent;

    switch (flags) {
    case DIROPS_SYMLINK:
    case DIROPS_HARDLINK:
    case DIROPS_FILEOP:
        is_parent = false;
        break;
    default:
        is_parent = true;
    }

    if ((relpath = vfs_relpath(path, is_parent)) == NULL) {
        log_warn("getting relpath `%s` FAILED", path);
        return NULL;
    }

    /* if we are NOT looking up the root dentry */
    if (strlen(relpath)) {
        dentry = path_walk(tree->root_dentry, path_build, relpath);
    } else {
        dentry = tree->root_dentry;
    }

    if (dentry && (dirnode = metadata_get_dirnode(path_build, dentry))) {
        atomic_fetch_add(&dentry->count, 1);
    }

    *pp_dentry = dentry;
done:
    sdsfree(relpath);
    return dirnode;
}

dentry_t *
dentry_lookup(const char * path, lookup_flags_t flags)
{
    struct uc_dentry * dentry;
    path_builder_t path_list;

    struct dentry_tree * tree = vfs_tree(path);
    if (tree == NULL) {
        log_fatal("not a valid path: %s", path);
        return false;
    }

    TAILQ_INIT(&path_list);
    uc_dirnode_t * dirnode
        = _dcache_lookup(tree, &path_list, &dentry, path, flags);
    free_path_builder(&path_list);

    return dentry;
}

uc_filebox_t *
dcache_filebox(const char * path, size_t size_hint, uc_xfer_op_t xfer_op)
{
    int err, jrnl;
    const shadow_t * shdw;
    char *fname = NULL, *temp = NULL, *temp2 = NULL;
    sds path_link = NULL, fbox_path = NULL;
    ucafs_entry_type atype;
    const link_info_t * link_info = NULL;
    uc_filebox_t * fb = NULL;
    struct uc_dentry * dentry;
    path_builder_t path_list;
    uc_dirnode_t * dirnode;

    struct dentry_tree * tree = vfs_tree(path);
    if (tree == NULL) {
        log_fatal("not a valid path: %s", path);
        return false;
    }

    TAILQ_INIT(&path_list);

    dirnode = _dcache_lookup(tree, &path_list, &dentry, path, DIROPS_FILEOP);
    if (dirnode == NULL) {
        return NULL;
    }

    if ((fname = do_get_fname(path)) == NULL) {
        return NULL;
    }

    /* get the entry in the file */
    shdw = dirnode_traverse(dirnode, fname, UC_ANY, &atype, &jrnl, &link_info);
    if (shdw == NULL) {
        goto out;
    }

    /* if we are loading a link, then the codename should point to its info */
    if (link_info) {
        if (link_info->target_link[0] == '/') {
            // we have an absolute path
            // send request here
            fb = dcache_filebox(link_info->target_link, size_hint, xfer_op);
            goto out;
        } else {
            // have an relative path
            path_link = do_get_dir(path);
            path_link = sdscat(path_link, "/");
            path_link = sdscat(path_link, link_info->target_link);

            fb = dcache_filebox(path_link, size_hint, xfer_op);
            sdsfree(path_link);
            goto out;
        }
    }

    /* check if the user has rights */
    acl_rights_t right = (xfer_op == UCAFS_STORE) ? ACCESS_WRITE : ACCESS_READ;
    if (dirnode_checkacl(dirnode, right)) {
        log_error("[check_acl] %s ~> %s", path,
                  (right == ACCESS_WRITE ? "write" : "read"));
        goto out;
    }

    fb = metadata_get_filebox(dentry, dirnode, &path_list, shdw, size_hint,
                              jrnl);
out:
    sdsfree(fbox_path);

    if (link_info) {
        free((link_info_t *)link_info);
    }

    free_path_builder(&path_list);

    // TODO put dirnode

    sdsfree(fname);
    return fb;
}
