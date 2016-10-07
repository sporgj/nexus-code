include header.mk
include sgx_defs.mk

OPENAFS_PATH := $(HOME)/openafs
OPENAFS_INC := $(OPENAFS_PATH)/include
OPENAFS_SRC := $(OPENAFS_PATH)/src
OPENAFS_LIB := $(OPENAFS_PATH)/lib

OBJS := uc_rpc.o afsx.ss.o enclave_u.o $(OBJS)
RXGEN = $(OPENAFS_SRC)/rxgen/rxgen

RXINC := -I$(OPENAFS_INC)
RXLIBS := $(OPENAFS_LIB)/librx.a $(OPENAFS_LIB)/liblwp.a #-L$(OPENAFS_LIB) -lrx -llwp

CFLAGS += $(App_C_Flags)
CPPFLAGS += $(App_Cpp_Flags)

all: ucafs

copyconfig:
	cp mbedtls-config.h mbedtls/include/mbedtls/config.h

cryptolib: copyconfig
	cd mbedtls/library && make clean && make SHARED=t


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

third/libthird.a:
	make -C third/

libthird.a: third/libthird.a
	cp $^ $@

libucafs.a: $(OBJS) libthird.a
	@ar cr $@ $(OBJS) third/*.o
	@echo "ar => $@"

uc_rpc.o: uc_rpc.c afsx.ss.c
	$(CC) $(CFLAGS) $(RXINC) -c $< -o $@
	@echo "CC <= $@"

%.o: %.cc %.h
	@$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

%.o: %.c %.h
	@$(CC) $(CFLAGS) $(App_C_Flags) $(INCFLAGS) -c $< -o $@
	@echo "CC <= $@"

uc_dirnode.o: uc_dirnode.cc uc_dirnode.h dnode.pb.cc
	@$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@
	@echo "CXX <= $@"

uc_filebox.o: uc_filebox.cc uc_filebox.h fbox.pb.cc
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
