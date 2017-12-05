include build.mk

nexus_home := $(PWD)
build_path := $(nexus_home)/build/

nexus_frontends := 	frontend_afs \
#			frontend_stub

nexus_backends  :=	backend_sgx \
#		     	backend_stub

nexus_metadata_store := metadata_store

release_components :=   libnexus.a \
			backend_sgx.so \
			frontend_afs.a \
			libmbedcrypto.a \
			metadata_store.a

create_volume_components := \
	nexus_create_volume.o \
	libnexus.a \
	backend_sgx.so \
	libmbedcrypto.a \
	metadata_store.a


LDFLAGS := -L$(nexus_home)/mbedtls-2.6.0/library \
	   -L$(SGX_SDK)/lib64

libs :=  -luuid -lpthread


ifeq ($(SGX_MODE), SIM)
	libs += -lsgx_urts_sim -lsgx_uae_service_sim
else ifeq ($(SGX_MODE), HW)
	libs += -lsgx_urts -lsgx_uae_service
else
        $(error Invalid SGX MODE)
endif



build = \
        @if [ -z "$V" ]; then \
                echo '   [$1]     $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi




all: mbedtls frontends backends metadata_store libnexus nx-create-volume
	@$(CC) $(addprefix $(build_path),$(release_components) $(release_components)) $(LDFLAGS) $(libs) -o nexus
	@echo "GEN => $@"

dev: frontends backends metadata_store libnexus
# link the debug versions
	$(CC) $(addprefix $(build_path), libnexus.a metadata_store.a backend_stub.a frontend_afs.a libnexus.a)  -luuid -o nexus-afs-test
	$(CC) $(addprefix $(build_path), libnexus.a metadata_store.a backend_sgx.a  frontend_stub.a libnexus.a) -luuid -o nexus-sgx-test



frontends: $(nexus_frontends)

$(nexus_frontends):
	$(call build,BUILDING, make -C $@)




backends: $(nexus_backends)

$(nexus_backends):
	$(call build,BUILDING, make -C $@)


metadata_store:
	$(call build,BUILDING, make -C $@)


libnexus:
	$(call build,BUILDING, make -C $@)

nx-create-volume: libnexus
	@$(CC) $(addprefix $(build_path),$(create_volume_components)) $(LDFLAGS) $(libs) -luuid -o $@
	@echo "GEN => $@"


mbedtls:
	make -C $(nexus_home)/mbedtls-2.6.0/library SHARED=1
	@cp mbedtls-2.6.0/library/libmbedcrypto.a ./build



clean:
	make -C $(nexus_home)/libnexus clean
	make -C $(nexus_home)/mbedtls-2.6.0/library clean
	@$(foreach frontend,$(nexus_frontends), make -C $(nexus_home)/$(frontend) clean)
	@make -C $(nexus_home)/$(nexus_metadata_store) clean
	@$(foreach backend,$(nexus_backends), make -C $(nexus_home)/$(backend) clean)
	rm -f nx-create-volume nexus nexus_enclave.signed.so


.PHONY: debug libnexus frontends $(nexus_frontends) backends $(nexus_backends) metadata_store clean mbedtls
