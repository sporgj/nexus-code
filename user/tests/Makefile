UCAFS_DIR := ..
TEST_ENV := 1

include $(UCAFS_DIR)/header.mk
include $(UCAFS_DIR)/sgx_defs.mk

LIBS += $(App_Link_Flags) -lgtest -lgtest_main

TESTS = test_fetchstore test_dirops test_dcache

all: clean tests

tests: $(TESTS)

libucafs.a: ../libucafs.a
	make -C ../ && cp $< $@

test_%: test_%.cc uc_test.h libucafs.a
	@$(CXX) $(CPPFLAGS) $(App_Cpp_Flags) -I$(UCAFS_DIR) $< ../libucafs.a $(LIBS) -o $@
	@echo "$(CXX) => $@"

#define make-test-target
#$(1): $(1).c libucafs.a
#	$(CXX) -DTEST_ENV $$(CPPFLAGS) -I./ $$(INCFLAGS) $(1).c\
#		libucafs.a $$(LIBS) $$(App_Link_Flags) -lcheck -o $(1)
#	@echo "CXX <= $(1)"
#endef

#$(foreach element,$(TESTS),$(eval $(call make-test-target,tests/$(element))))
#tests: $(addprefix tests/, $(TESTS))

.PHONY: clean
clean: repo/.afsx
	rm -rf repo/.afsx/* *.o *.a

repo/.afsx:
	mkdir -p $@
