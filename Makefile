nexus_home := $(PWD)
build_path := $(nexus_home)/build

nexus_frontends := 	frontend_afs \
#			frontend_stub

nexus_backends  :=	backend_sgx \
#		     	backend_stub


release_components :=   libnexus.a \
			backend_sgx.a \
			frontend_afs.a


build = \
        @if [ -z "$V" ]; then \
                echo '   [$1]     $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi




all: frontends backends libnexus
	$(CC) $(addprefix $(build_path),$(release_components)) -luuid -o nexus

dev: frontends backends libnexus
# link the debug versions
	$(CC) $(addprefix $(build_path), libnexus.a backend_stub.a frontend_afs.a)  -luuid -o nexus-afs-test
	$(CC) $(addprefix $(build_path), libnexus.a backend_sgx.a  frontend_stub.a) -luuid -o nexus-sgx-test



frontends: $(nexus_frontends)

$(nexus_frontends):
	$(call build,BUILDING, make -C $@)




backends: $(nexus_backends)

$(nexus_backends):
	$(call build,BUILDING, make -C $@)



libnexus:
	$(call build,BUILDING, make -C $@)





clean:
	make -C $(nexus_home)/libnexus clean
	@$(foreach frontend,$(nexus_frontends), make -C $(nexus_home)/$(frontend) clean)
	@$(foreach backend,$(nexus_backends), make -C $(nexus_home)/$(backend) clean)


.PHONY: debug libnexus frontends $(nexus_frontends) backends $(nexus_backends) clean
