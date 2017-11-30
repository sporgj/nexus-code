nexus_home := $(PWD)


nexus_frontends := 	frontend_afs \
#			frontend_stub

nexus_backends  :=	backend_sgx \
#		     	backend_stub



invoke = \
	@if [ true ]; then \
                echo ' [Building $1]' ; \
                make -C $(nexus_home)/$1; \
	fi

all: libnexus frontends backends


.PHONY: libnexus frontends $(nexus_frontends) backends $(nexus_backends)


frontends: $(nexus_frontends)

$(nexus_frontends):
	$(call invoke,$@)




backends: $(nexus_backends)

$(nexus_backends):
	$(call invoke,$@)



libnexus:
	make -C $(nexus_home)/libnexus


.PHONY: clean
clean:
	make -C $(nexus_home)/libnexus clean
	@$(foreach frontend,$(nexus_frontends), make -C $(nexus_home)/$(frontend) clean)
	@$(foreach backend,$(nexus_backends), make -C $(nexus_home)/$(backend) clean)
