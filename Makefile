nexus_home := $(PWD)


nexus_frontends := 	frontend_afs \
#			frontend_stub

nexus_backends  :=	backend_sgx \
#		     	backend_stub



invoke = \
                echo ' [Building $1]' ; \
                cd $(nexus_home)/$1 && make || exit


all: libnexus frontends backends



frontends:
	@$(foreach frontend,$(nexus_frontends), $(call invoke,$(frontend)))

backends:
	@$(foreach backend,$(nexus_backends), $(call invoke,$(backend)))




libnexus:
	make -C $(nexus_home)/libnexus


.PHONY: clean
clean:
	make -C $(nexus_home)/libnexus clean
	@$(foreach frontend,$(nexus_frontends), make -C $(nexus_home)/$(frontend) clean)
	@$(foreach backend,$(nexus_backends), make -C $(nexus_home)/$(backend) clean)
