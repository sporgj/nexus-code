#include <gperftools/heap-profiler.h>
#include <gtest/gtest.h>

extern "C" {
#include <uc_dirnode.h>
#include <uc_dirops.h>
#include <uc_encode.h>
#include <uc_sgx.h>
#include <uc_uspace.h>
#include <uc_utils.h>

#include <third/log.h>

int
start_testbed();
};
