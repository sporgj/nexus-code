/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#pragma once

#include "users.h"
#include "supernode.h"

struct backend_state {
    struct supernode * supernode;
    struct user_list * user_list;
    struct user      * user;
};


extern struct backend_state active_volume;
