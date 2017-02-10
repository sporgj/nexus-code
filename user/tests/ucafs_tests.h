#include <gtest/gtest.h>
#include <gperftools/heap-profiler.h>

extern "C" {
#include <cdefs.h>

#include <uc_dirnode.h>
#include <uc_sgx.h>
#include <uc_uspace.h>
#include <uc_encode.h>

#include <third/log.h>

};
