# NEXUS

Practical and Secure Access Control on Untrusted Storage Platforms using
Client-side SGX.

## Setup Instructions
```bash
cd openafs
./regen.sh
./configure --prefix=$(HOME)/local
make
make install

make -C libnexus        # builds the nexus vfs core library
make -C afs_frontend    # builds the application

sudo mkdir /afs
sudo isnmod $(HOME)/local/lib/openafs/libafs*.ko
sudo $(HOME)/local/sbin/afsd
kinit alice
$(HOME)/local/bin/aklog



```

## Code Structure

[docs](docs)
.. Documentation and other user guides

[openafs](openafs)
.. The openafs source code. Currently based on v1.6.18

[openafs/shimlayer](openafs/shimlayer)
.. The code for the kernel space shim layer.
