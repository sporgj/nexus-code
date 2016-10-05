#pragma once

#include <iostream>

#include <encode.h>
#include <uc_dnode.h>
#include <uc_dirops.h>
#include <uc_utils.h>
#include <enclave_common.h>

extern "C" int setup_rx(int);
extern "C" int dcache_init(void);

#define TEST_AFS_HOME "repo"
