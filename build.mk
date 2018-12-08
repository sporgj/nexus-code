######## SGX SDK Settings ########
SGX_SDK   ?= /home/pranut/Downloads/linux-sgx/linux/installer/bin/sgxsdk

# Can be either 'HW' or 'SIM'
SGX_MODE  := SIM


DEBUG := 1

# to enable compiler intrinsics
LIBGCC_PATH := $(shell gcc -print-file-name=include)

DTRACE_ENABLED := 0
