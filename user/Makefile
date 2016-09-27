include header.mk
include sgx_defs.mk

OPENAFS_PATH := $(HOME)/openafs
OPENAFS_INC := $(OPENAFS_PATH)/include
OPENAFS_SRC := $(OPENAFS_PATH)/src
OPENAFS_LIB := $(OPENAFS_PATH)/lib

OBJS := rpc.o afsx.ss.o enclave_u.o $(OBJS)
RXGEN = $(OPENAFS_SRC)/rxgen/rxgen

RXINC := -I$(OPENAFS_INC)
RXLIBS := -L$(OPENAFS_LIB) -lrx -llwp

CPPFLAGS += $(App_Cpp_Flags)

all: ucafs

copyconfig:
	cp mbedtls-config.h mbedtls/include/mbedtls/config.h

cryptolib: copyconfig
	cd mbedtls/library && make clean && make SHARED=t

define make-test-target
$(1): $(1).cc libucafs.a
	@$(CXX) -DTEST_ENV $$(CPPFLAGS) -I./ $$(INCFLAGS) $(1).cc\
		libucafs.a $$(LIBS) $$(App_Link_Flags) -o $(1)
	@echo "CXX <= $(1)"
endef

$(foreach element,$(TESTS),$(eval $(call make-test-target,tests/$(element))))
tests: $(addprefix tests/, $(TESTS)) tests/test_upload

tests/test_upload: tests/test_upload.cc libucafs.a afsx.cs.o
	@$(CXX) -DTEST_ENV $(CPPFLAGS) -I./ $(INCFLAGS) $(RXINC) $^ $(LIBS)\
		$(RXLIBS) $(App_Link_Flags) -o $@
	@echo "CXX <= $@"

enclave_u.c: sgx/enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^
	@echo "GEN =>  $@"

enclave_u.o: enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC <= $^"

afsx.cs.o: afsx.cs.c afsx.h
	@$(CC) $(CFLAGS) $(RXINC) -c $< -o $@
	@echo "CC <= $@"

afsx.cs.c: afsx.xg
	$(RXGEN) -A -x -C -o $@ $<

ucafs: main.cc libucafs.a
	@$(CXX) $(CPPFLAGS) $^ $(LIBS) $(RXLIBS) $(App_Link_Flags) -o $@
	@echo "CXX <= $@"

afsx.ss.o: afsx.ss.c
	@$(CC) $(CFLAGS) $(RXINC) -c $< -o $@
	@echo "CC <= $@"

afsx.ss.c: afsx.xg afsx.h
	$(RXGEN) -A -x -S -o $@ $<

afsx.h: afsx.xg afsx_hdr.h
	$(RXGEN) -A -x -h -o $@ $<

libucafs.a: $(OBJS)
	@ar cr $@ $^
	@echo "ar => $@"

rpc.o: rpc.c afsx.ss.c
	@$(CC) $(CFLAGS) $(RXINC) -c $< -o $@
	@echo "CC <= $@"

%.o: %.cc %.h
	@$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

%.o: %.c %.h
	@$(CC) $(CFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

dirnode.o: dirnode.cc dirnode.h dnode.pb.cc
	@$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

filebox.o: filebox.cc filebox.h fbox.pb.cc
	@$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

%.pb.o: %.pb.cc
	@$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

%.pb.cc: %.proto
	protoc --cpp_out=./ $^

.PHONY: clean
clean:
	rm -rf $(GENS) $(PROGRAM) *.o
