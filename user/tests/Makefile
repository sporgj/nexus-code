UCAFS_DIR := ..

include $(UCAFS_DIR)/header.mk
include $(UCAFS_DIR)/sgx_defs.mk

LIBS += $(App_Link_Flags) -lgtest

TESTS = test_dirops

all: clean tests

tests: $(TESTS)

test_dirops: test_dirops.cc uc_test.h
	@$(CXX) $(CPPFLAGS) -I$(UCAFS_DIR) $< ../libucafs.a $(LIBS) -o $@
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
	rm -rf repo/.afsx/* *.o

repo/.afsx:
	mkdir -p $@
