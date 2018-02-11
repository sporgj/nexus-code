#include "enclave_internal.h"

struct __user {
    nexus_user_flags_t flags;

    struct nexus_uuid  user_uuid; // user's unique identifier

    pubkey_hash_t      pubkey;

    char               name[NEXUS_MAX_NAMELEN]; // XXX  future 0 byte array impl...
} __attribute__((packed));

// my initial iteration has the usertable embedded inside the supernode (which is
// practically empty at this point).
struct __table_hdr {
    struct nexus_uuid uuid;

    uint32_t          total_size;

    uint32_t          user_count;
} __attribute__((packed));

struct nexus_usertable {
    struct nexus_uuid uuid;

    struct nexus_uuid supernode_uuid;

    struct nexus_list userlist;
};


static void
free_user(struct nexus_user * user)
{
    nexus_free(user->name);
    nexus_free(user);
}

static void
init_userlist(struct nexus_usertable * usertable)
{
    nexus_list_init(&usertable->userlist);
    nexus_list_set_deallocator(&usertable->userlist, free_user);
}

struct nexus_usertable *
nexus_usertable_create(struct nexus_uuid * supernode_uuid)
{
    struct nexus_usertable * usertable = NULL;

    usertable = nexus_malloc(sizeof(struct nexus_usertable));


    nexus_uuid_gen(&usertable->uuid);
    nexus_uuid_copy(supernode_uuid, &usertable->supernode_uuid);

    init_userlist(usertable);

    return usertable;
}


void
nexus_usertable_free(struct nexus_usertable * usertable)
{
    nexus_list_destroy(&usertable->userlist);
    nexus_free(usertable);
}

struct nexus_usertable * usertable
nexus_usertable_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct nexus_usertable * usertable = NULL;

    uint8_t * input_ptr = NULL;

    /// parse the buffers here
}
