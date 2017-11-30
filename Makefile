nexus_home := $(PWD)


nexus_frontends := 	frontend_afs \
#			frontend_stub

nexus_backends  :=	backend_sgx \
#		     	backend_stub




build = \
        @if [ -z "$V" ]; then \
                echo '   [$1]     $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi

all: libnexus frontends backends
# link release version (AFS + SGX)

dev: libnexus frontends backends
# link the debug versions



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
