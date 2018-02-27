/**
 * The code is adapted from stackfs by Bharath Kumar Reddy Vangoor
 * https://github.com/sbu-fsl/fuse-stackfs
 */


/*=============Hash Table implementation==========================*/

/* The node structure that we maintain as our local cache which maps
 * the ino numbers to their full path, this address is stored as part
 * of the value of the hash table */
struct lo_inode {
    struct lo_inode * next;
    struct lo_inode * prev;
    /* Full path of the underlying ext4 path
     * correspoding to its ino (easy way to extract back) */
    char * name;
    /* Inode numbers and dev no's of
     * underlying EXT4 F/s for the above path */
    ino_t ino;
    dev_t dev;
    /* inode number sent to lower F/S */
    ino_t lo_ino;
    /* Lookup count of this node */
    uint64_t nlookup;
};

#define HASH_TABLE_MIN_SIZE 8192

/* The structure is used for maintaining the hash table
 * 1. array	--> Buckets to store the key and values
 * 2. use	--> Current size of the hash table
 * 3. size	--> Max size of the hash table
 * (we start with NODE_TABLE_MIN_SIZE)
 * 4. split	--> used to resize the table
 * (this is how fuse-lib does) */
struct node_table {
    struct lo_inode ** array;
    size_t             use;
    size_t             size;
    size_t             split;
};

static int
hash_table_init(struct node_table * t)
{
    t->size  = HASH_TABLE_MIN_SIZE;
    t->array = (struct lo_inode **)calloc(1, sizeof(struct lo_inode *) * t->size);
    if (t->array == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }
    t->use   = 0;
    t->split = 0;

    return 0;
}

void
hash_table_destroy(struct node_table * t)
{
    free(t->array);
}

static int
hash_table_resize(struct node_table * t)
{
    size_t newsize  = t->size * 2;
    void * newarray = NULL;

    newarray = realloc(t->array, sizeof(struct lo_inode *) * newsize);
    if (newarray == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }

    t->array = newarray;
    /* zero the newly allocated space */
    memset(t->array + t->size, 0, t->size * sizeof(struct lo_inode *));
    t->size  = newsize;
    t->split = 0;

    return 0;
}

/* The structure which is used to store the hash table
 * and it is always comes as part of the req structure */
struct lo_data {
    /* hash table mapping key (inode no + complete path) -->
     *  value (linked list of node's - open chaining) */
    struct node_table hash_table;
    /* protecting the above hash table */
    pthread_spinlock_t spinlock;
    /* put the root Inode '/' here itself for faster
     * access and some other useful raesons */
    struct lo_inode root;
    /* do we still need this ? let's see*/
    double attr_valid;
};

struct lo_dirptr {
    DIR *           dp;
    struct dirent * entry;
    off_t           offset;
};

static struct lo_dirptr *
lo_dirptr(struct fuse_file_info * fi)
{
    return ((struct lo_dirptr *)((uintptr_t)fi->fh));
}

static struct lo_data *
get_lo_data(fuse_req_t req)
{
    return (struct lo_data *)fuse_req_userdata(req);
}

static struct lo_inode *
lo_inode(fuse_req_t req, fuse_ino_t ino)
{
    if (ino == FUSE_ROOT_ID)
        return &get_lo_data(req)->root;
    else
        return (struct lo_inode *)(uintptr_t)ino;
}

static char *
lo_name(fuse_req_t req, fuse_ino_t ino)
{
    return lo_inode(req, ino)->name;
}

/* This is what given to the kernel FUSE F/S */
static ino_t
get_lower_fuse_inode_no(fuse_req_t req, fuse_ino_t ino)
{
    return lo_inode(req, ino)->lo_ino;
}

/* This is what given to the user FUSE F/S */
// static ino_t get_higher_fuse_inode_no(fuse_req_t req, fuse_ino_t ino) {
//	return lo_inode(req, ino)->ino;
//}

static double
lo_attr_valid_time(fuse_req_t req)
{
    return ((struct lo_data *)fuse_req_userdata(req))->attr_valid;
}

static void
construct_full_path(fuse_req_t req, fuse_ino_t ino, char * fpath, const char * path)
{
    strcpy(fpath, lo_name(req, ino));
    strncat(fpath, "/", 1);
    strncat(fpath, path, PATH_MAX);
}

/*======================End=======================================*/

/* Function which generates the hash depending on the ino number
 * and full path */
static size_t
name_hash(struct lo_data * lo_data, fuse_ino_t ino, const char * fullpath)
{
    uint64_t     hash = ino;
    uint64_t     oldhash;
    const char * name;

    name = fullpath;

    for (; *name; name++)
        hash = hash * 31 + (unsigned char)*name;

    hash %= lo_data->hash_table.size;
    oldhash = hash % (lo_data->hash_table.size / 2);
    if (oldhash >= lo_data->hash_table.split)
        return oldhash;
    else
        return hash;
}

static void
remap_hash_table(struct lo_data * lo_data)
{
    struct node_table * t = &lo_data->hash_table;
    struct lo_inode **  nodep;
    struct lo_inode **  next;
    struct lo_inode *   prev;
    size_t              hash;

    if (t->split == t->size / 2)
        return;

    /* split this bucket by recalculating the hash */
    hash = t->split;
    t->split++;

    for (nodep = &t->array[hash]; *nodep != NULL; nodep = next) {
        struct lo_inode * node    = *nodep;
        size_t            newhash = name_hash(lo_data, node->ino, node->name);

        if (newhash != hash) {
            prev   = node->prev;
            *nodep = node->next;
            if (*nodep)
                (*nodep)->prev = prev;

            node->prev = NULL;
            node->next = t->array[newhash];
            if (t->array[newhash])
                (t->array[newhash])->prev = node;
            t->array[newhash]             = node;
            next                          = nodep;
        } else {
            next = &node->next;
        }
    }

    /* If we have reached the splitting to half of the size
     * then double the size of hash table */
    if (t->split == t->size / 2)
        hash_table_resize(t);
}

static int
insert_to_hash_table(struct lo_data * lo_data, struct lo_inode * lo_inode)
{
    size_t hash = name_hash(lo_data, lo_inode->ino, lo_inode->name);

    lo_inode->next = lo_data->hash_table.array[hash];
    if (lo_data->hash_table.array[hash])
        (lo_data->hash_table.array[hash])->prev = lo_inode;
    lo_data->hash_table.array[hash]             = lo_inode;
    lo_data->hash_table.use++;

    if (lo_data->hash_table.use >= lo_data->hash_table.size / 2)
        remap_hash_table(lo_data);

    return 0;
}

static void
hash_table_reduce(struct node_table * t)
{
    size_t newsize = t->size / 2;
    void * newarray;

    if (newsize < HASH_TABLE_MIN_SIZE)
        return;

    newarray = realloc(t->array, sizeof(struct node *) * newsize);
    if (newarray != NULL)
        t->array = newarray;

    t->size  = newsize;
    t->split = t->size / 2;
}

static void
remerge_hash_table(struct lo_data * lo_data)
{
    struct node_table * t = &lo_data->hash_table;
    int                 iter;

    /* This means all the hashes would be under the half size
     * of table (so simply make it half) */
    if (t->split == 0)
        hash_table_reduce(t);

    for (iter = 8; t->split > 0 && iter; iter--) {
        struct lo_inode ** upper;

        t->split--;
        upper = &t->array[t->split + t->size / 2];
        if (*upper) {
            struct lo_inode ** nodep;
            struct lo_inode *  prev = NULL;

            for (nodep = &t->array[t->split]; *nodep; nodep = &(*nodep)->next)
                prev = *nodep;

            *nodep         = *upper;
            (*upper)->prev = prev;
            *upper         = NULL;
            break;
        }
    }
}

static int
delete_from_hash_table(struct lo_data * lo_data, struct lo_inode * lo_inode)
{
    struct lo_inode *prev, *next;

    prev = next = NULL;
    size_t hash = 0;

    pthread_spin_lock(&lo_data->spinlock);

    prev = lo_inode->prev;
    next = lo_inode->next;

    if (prev) {
        prev->next = next;
        if (next)
            next->prev = prev;
        goto del_out;
    } else {
        hash = name_hash(lo_data, lo_inode->ino, lo_inode->name);

        if (next)
            next->prev = NULL;

        lo_data->hash_table.array[hash] = next;
    }

del_out:
    /* free the lo_inode  */
    lo_inode->prev = lo_inode->next = NULL;
    free(lo_inode->name);
    free(lo_inode);

    lo_data->hash_table.use--;
    if (lo_data->hash_table.use < lo_data->hash_table.size / 4)
        remerge_hash_table(lo_data);

    pthread_spin_unlock(&lo_data->spinlock);
    return 0;
}

/* Function which checks the inode in the hash table
 * by calculating the hash from ino and full path */
static struct lo_inode *
lookup_lo_inode(struct lo_data * lo_data, struct stat * st, const char * fullpath)
{
    size_t            hash = name_hash(lo_data, st->st_ino, fullpath);
    struct lo_inode * node;

    for (node = lo_data->hash_table.array[hash]; node != NULL; node = node->next) {
        if ((node->ino == st->st_ino) && (node->dev == st->st_dev)
            && (strcmp(node->name, fullpath) == 0))
            return node;
    }

    return NULL;
}

void
free_hash_table(struct lo_data * lo_data)
{
    struct lo_inode *node, *next;

    size_t i;

    for (i = 0; i < lo_data->hash_table.size; i++) {
        node = lo_data->hash_table.array[i];
        while (node) {
            next = node->next;
            /* free up the node */
            free(node->name);
            free(node);
            node = next;
        }
    }
}

/* A function which checks the hash table and returns the lo_inode
 * otherwise a new lo_inode is created and inserted into the hashtable
 * req		--> for the hash_table reference
 * st		--> to check against the ino and dev_id
 *			when navigating the bucket chain
 * fullpath	--> full path is used to construct the key */
struct lo_inode *
find_lo_inode(fuse_req_t req, struct stat * st, char * fullpath)
{
    struct lo_data *  lo_data;
    struct lo_inode * lo_inode;
    int               res;

    lo_data = get_lo_data(req);

    pthread_spin_lock(&lo_data->spinlock);

    lo_inode = lookup_lo_inode(lo_data, st, fullpath);

    if (lo_inode == NULL) {
        /* create the node and insert into hash_table */
        lo_inode = calloc(1, sizeof(struct lo_inode));
        if (!lo_inode)
            goto find_out;
        lo_inode->ino  = st->st_ino;
        lo_inode->dev  = st->st_dev;
        lo_inode->name = strdup(fullpath);
        /* store this for mapping (debugging) */
        lo_inode->lo_ino = (uintptr_t)lo_inode;
        lo_inode->next = lo_inode->prev = NULL;

        /* insert into hash table */
        res = insert_to_hash_table(lo_data, lo_inode);
        if (res == -1) {
            free(lo_inode->name);
            free(lo_inode);
            lo_inode = NULL;
            goto find_out;
        }
    }
    lo_inode->nlookup++;
find_out:
    pthread_spin_unlock(&lo_data->spinlock);
    return lo_inode;
}
