include header.mk

APP_PATH = ../
OBJS = ecall_sgx.o

.PHONY: all
all: enclave.signed.so

# untrusted objects
$(APP_PATH)/enclave_u.c: enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir $(APP_PATH) $^
	@echo "GEN =>  $@"

$(APP_PATH)/enclave_u.o: $(APP_PATH)/enclave_u.c
	@$(CC) -c $< -o $@
	@echo "CC <= $^"


#trusted
%.o: %.cc
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX => $@"

private_key.pem:
	openssl genrsa -out $@ -3 3072

enclave_t.c: enclave.edl
	@$(SGX_EDGER8R) --trusted --trusted-dir . $^
	@echo "GEN +> $@"

enclave_t.o: enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC => $@"

enclave.so: enclave_t.o $(OBJS)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK => $@"

enclave.signed.so: enclave.so private_key.pem
	@$(SGX_ENCLAVE_SIGNER) sign -key private_key.pem -enclave $< -out $@ -config config.xml
	@echo "SIGN => $@"

.PHONY: clean
clean:
	rm -rf *.so *.o enclave_t.*
