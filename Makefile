AFS_FRONTEND_DIRPATH := afs_frontend
AFS_FRONTEND_LIBPATH := $(AFS_DIRPATH)/afs_frontend.a

LIBNEXUS_DIRPATH := libnexus 
LIBNEXUS_LIDPATH := $(LIBNEXUS_DIRPATH)/libnexus.a

SGX_BACKEND_DIRPATH := sgx_backend
SGX_BACKEND_LIBPATH := $(SGX_BACKEND_DIRPATH)/sgx_backend.a

# we default to afs frontend
FRONTEND = $(AFS_FRONTEND_DIRPATH)

all: afs_sgx_hw_debug

.PHONY: set_afs_frontend
set_afs_frontend: FRONTEND := $(AFS_FRONTEND_DIRPATH)

.PHONY: afs_sgx_hw_debug
afs_sgx_hw_debug: set_afs_frontend
afs_sgx_hw_debug: build_afs build_libnexus build_sgx_hw_debug
	@echo "[[ Building $@ => AFS frontend with SGX backend in Hardware+debug mode ]]"
	@echo "ok $(FRONTEND)"

.PHONY: afs_sgx_sim_debug
afs_sgx_sim_debug: set_afs_frontend
afs_sgx_sim_debug:
	@echo "Building $@ => AFS frontend with SGX backend in SIM+debug mode"

.PHONY: build_afs
build_afs:
	make -C $(AFS_FRONTEND_DIRPATH)

.PHONY: build_libnexus
build_libnexus:
	make -C $(LIBNEXUS_DIRPATH)

.PHONY: build_sgx_sim_debug
build_sgx_sim_debug:
	make -C $(SGX_BACKEND_DIRPATH) SGX_DEBUG=1 SGX_MODE=SIM

.PHONY: build_sgx_hw_debug
build_sgx_hw_debug:
	make -C $(SGX_BACKEND_DIRPATH) SGX_DEBUG=1 SGX_MODE=HW

.PHONY: clean
clean:
	make -C $(AFS_FRONTEND_DIRPATH) clean
	make -C $(LIBNEXUS_DIRPATH) clean
	make -C $(SGX_BACKEND_DIRPATH) clean
