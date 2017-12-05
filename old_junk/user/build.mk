# File defines configuration for release/debug/hw/sim

SGX_MODE := SIM
SGX_ARCH := x64
SGX_DEBUG := 1
SGX_PRELEASE := 0

# enable SGX ecalls
UCAFS_SGX := 1

# are we running a development build
UCAFS_DEV := 1

# if to add the profiler
UCAFS_PROFILER := 1

# if to flush the entries or nah
UCAFS_FLUSH := 0
