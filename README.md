# NEXUS

Practical and Secure Access Control on Untrusted Storage Platforms using
Client-side SGX.

## Setup Instructions
```bash
cd openafs
./regen.sh
./configure-libafs
make libafs
make venus

cp openafs/src/aklog/aklog ./bin
cp openafs/src/afsd/afsd ./bin
cp openafs/src/venus/fs ./bin
cp openafs/src/libafs/MODLOAD-4.4.0-62-generic-MP/libafs.ko ./

make -C libnexus        # builds the nexus vfs core library
make -C afs_frontend    # builds the application
```

## Code Structure

[docs](docs)
.. Documentation and other user guides

[openafs](openafs)
.. The openafs source code. Currently based on v1.6.18

[openafs/shimlayer](openafs/shimlayer)
.. The code for the kernel space shim layer.
