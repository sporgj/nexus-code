include build.mk

nexus_home := $(PWD)
build_path := $(nexus_home)/build/

nexus_frontends := 	frontend_afs \
			shell

nexus_backends  :=     	backend_clear \
#			backend_sgx

nexus_metadata_store := 
#metadata_store


components := libmbedcypto.a libnexus.a $(addsuffix .a, $(nexus_backends) $(nexus_metadata_store))

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




all: mbedtls backends metadata_store libnexus frontends



frontends: $(nexus_frontends)

$(nexus_frontends):
	$(call build,BUILDING, make -C $@)


backends: $(nexus_backends)

$(nexus_backends):
	$(call build,BUILDING, make -C $@)


$(metadata_store):
	$(call build,BUILDING, make -C $@)


libnexus:
	$(call build,BUILDING, make -C $@)
	$(call build,AR,$(AR) -M < libnexus.mri)


mbedtls:
	make -C $(nexus_home)/mbedtls-2.6.0/library SHARED=1
	@cp mbedtls-2.6.0/library/libmbedcrypto.a ./build



clean:
	make -C $(nexus_home)/libnexus clean
	make -C $(nexus_home)/mbedtls-2.6.0/library clean
#	@make -C $(nexus_home)/$(nexus_metadata_store) clean
	$(foreach frontend,$(nexus_frontends), make -C $(nexus_home)/$(frontend) clean;)
	$(foreach backend,$(nexus_backends), make -C $(nexus_home)/$(backend) clean;)


.PHONY: debug libnexus frontends $(nexus_frontends) backends $(nexus_backends) metadata_store clean mbedtls
