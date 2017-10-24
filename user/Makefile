include header.mk
include sgx_defs.mk

OBJS := uc_mod.o uc_rpc.o enclave_u.o $(OBJS)

CFLAGS += $(App_C_Flags) -std=gnu11
CPPFLAGS += $(App_Cpp_Flags)

all: ucafs admin_ucafs

copyconfig:
	cp mbedtls-config.h mbedtls/include/mbedtls/config.h

cryptolib: copyconfig
	cd mbedtls/library && make clean && make SHARED=t DEBUG=t

admin_ucafs: admin_ucafs.c libucafs.a
	@$(CC) $(CFLAGS) $^ $(LIBS) $(App_Link_Flags) -lmbedcrypto -o $@
	@echo "GEN => $@"

enclave_u.c: sgx/enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^
	@echo "GEN =>  $@"

enclave_u.o: enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC <= $^"

ucafs: main.c libucafs.a
	@$(CC) $(CFLAGS) $^ $(LIBS) $(App_Link_Flags) -o $@
	@echo "CXX <= $@"

third/libthird.a:
	make -C third/

libthird.a: third/libthird.a
	cp $^ $@

libucafs.a: $(OBJS) libthird.a
	@ar cr $@ $(OBJS) third/*.o
	@echo "ar => $@"

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC <= $@"



build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi




define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



.PHONY: clean
clean:
	rm -rf $(GENS) $(PROGRAM) *.o
