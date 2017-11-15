#pragma once

#include <nexus_untrusted.h>

#define UNITY_OUTPUT_COLOR
#include "unity/unity.h"

#define TEST_PUBLIC_KEY "profile/public_key"
#define TEST_PRIVATE_KEY "profile/private_key"

#define TEST_ENCLAVE_PATH "../enclave/nx_enclave.signed.so"

#ifndef RUN_TEST
#define RUN_TEST(testfunc)                                                     \
    UNITY_NEW_TEST(#testfunc)                                                  \
    if (TEST_PROTECT()) {                                                      \
        setUp();                                                               \
        testfunc();                                                            \
    }                                                                          \
    if (TEST_PROTECT() && (!TEST_IS_IGNORED))                                  \
        tearDown();                                                            \
    UnityConcludeTest();
#endif
