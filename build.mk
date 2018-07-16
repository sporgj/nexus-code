######## SGX SDK Settings ########
SGX_SDK   ?= /opt/intel/sgxsdk

# Can be either 'HW' or 'SIM'
SGX_MODE  := HW


DEBUG := 1

# to enable compiler intrinsics
LIBGCC_PATH := $(shell gcc -print-file-name=include)
