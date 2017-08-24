UCAFS_DIR := ..
TEST_ENV := 1

include $(UCAFS_DIR)/header.mk
include $(UCAFS_DIR)/sgx_defs.mk

LIBS += $(App_Link_Flags) -lgtest -lgtest_main

TESTBED_FILE = ucafs_testbed.c

TESTS = test_structs test_dirops

all: tests

tests: $(TESTS)

libucafs.a: ../libucafs.a
		make -C ../ && cp $< $@

test_structs: test_structs.cc libucafs.a
		@$(CXX) $(CPPFLAGS) $(App_Cpp_Flags) -I$(UCAFS_DIR) $< $(TESTBED_FILE)\
			../libucafs.a $(LIBS)  -o $@
		@echo "$(CXX) => $@"

test_dirops: test_dirops.cc libucafs.a
		@$(CXX) $(CPPFLAGS) $(App_Cpp_Flags) -I$(UCAFS_DIR) $< $(TESTBED_FILE)\
			../libucafs.a $(LIBS)  -o $@
		@echo "$(CXX) => $@"

.PHONY: clean
clean:
	rm -f $(TESTS) *.a *.o
