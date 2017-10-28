# NEXUS

Practical and Secure Access Control on Untrusted Storage Platforms using
Client-side SGX.

## Setup Instructions
```bash
make -C openafs         # builds openafs
./makelinks.sh          # creates the symlinks
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
