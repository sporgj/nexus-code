# Fetching Sources

## OpenAFS
```bash
git clone https://github.com/openafs/openafs
cd openafs
git checkout openafs-stable-1_6_18
```

## NeXUS
```
git clone https://gitlab.prognosticlab.org/sgx/nexus.git
```

# Installing OpenAFS
## Preliminaries

At this point, it is assumed you have a custom kernel. Otherwise, make sure you
get the headers. 
```
sudo apt-get install linux-headers-$(uname -r)
```

First, update package listings and install compiler toolchain.
```bash
sudo apt-get update
sudo apt-get install build-essential git autoconf automake\
    make libtool flex bison libc6-dev libkrb5-dev libperl-dev\
    libncurses5-dev libfuse-dev krb5-user
```

When asked for the kerberos realm, put `MAATTA.SGX` for now. It points to the
machine in Dr. Lange's lab and already has an AFS fileserver.

For the server: `136.142.119.35`. Enter the same value for the admin service.

## Setup Cache

Generate a huge file and mount it as an AFS partition in `/var/cache/openafs`.

```bash
sudo -s
cd /var/cache
dd if=/dev/zero of=openafs.img bs=100M count=30 # 3 GB
mkfs.ext4 openafs.img
sh -c "echo '/var/cache/openafs.img /var/cache/openafs ext4 defaults,loop 0 2' >> /etc/fstab"
tune2fs -c 0 -i 0 -m 0 openafs.img
mkdir openafs
mount openafs
exit
```

AFS requires 3 main files:
- cacheinfo: contains the locations of the afs tree and cache directory
- CellServDB: List of servers running AFS
- ThisCell: To which cell to primarily connect to.

Now, let's create the AFS cacheinfo. Note that the `2800000` below is meant to
be `90%` of the partition created above (3GB).
```bash
sudo -s
mkdir /afs # creates the afs tree
mkdir -p /usr/local/etc/openafs
cd /usr/local/etc/openafs
echo '/afs:/var/cache/openafs:2800000' > cacheinfo
```

The CellServDB needs to contain the location of our custom AFS server.
```bash
echo '>maatta.sgx' > CellServDB
echo '136.142.119.35          #afs-srv' >> CellServDB
echo 'maatta.sgx' > ThisCell
exit
```

## Building
```bash
cd ~/openafs    # return to the source code
./regen.sh
```

Now, let's apply the patch that enables the NeXUS daemon to connect to the
kernel.
```
patch -p1 < ~/nexus/module/openafs.afsx.patch
```

Traverse to the NeXUS module code and copy the source files
```
cd ~/nexus/module
make install        # this assumes that you have the sources installed
```

Return to OpenAFS and build it all. It should take some time :)
```
cd ~/openafs
./configure
make -j$(nproc)
```

Add `fs` ACL utility as a system binary.
```bash
sudo ln -s /home/$USER/openafs/src/venus/fs /usr/bin/fs
```
Before proceeding, make sure the `fs` command works. Otherwise, run `make`
in the `~/openafs/src/venus/` directory to build it.

The openafs module is now ready to be mounted in the kernel.
```bash
cd
cp nexus/start_afs.sh .
./start_afs.sh alice
```

When prompted for a password, type `sgx`. This authenticates a user `alice`
with the AFS server.


# Installing NeXUS
## Preliminaries
Let's first install the dependencies
```bash
sudo apt-get install uuid-dev libmbedtls-dev libuv1-dev libgoogle-perftools-dev cscope
```

Let's install the crypto library
```bash
wget https://tls.mbed.org/download/mbedtls-2.6.0-apache.tgz
tar -xf mbedtls-2.6.0-apache.tgz
rm mbedtls-2.6.0-apache.tgz
mv mbedtls-2.6.0/ mbedtls
make cryptolib
```

## Install SGX
Please follow the instructions on these pages.

[Linux SGX Driver](https://github.com/01org/linux-sgx-driver)
[Linux SGX & PSW](https://github.com/01org/linux-sgx)

## Build SGX enclave
The `build.mk` file contains the build configuration for the project.  As it is
setup, the repository builds in *simulator mode*, which allows to run the
enclave on non-SGX hardware.

PLEASE CHECK THE `build.mk` FILE.

Every time you change this file, please run `make clean && cd sgx && make clean`

Build the enclave and the application.
```bash
make -C sgx
make
```

## Initialize a nexus volume. 
This will create a volume in `/afs/maatta.sgx/user/alice/sgx`.
```bash
./init_ucafs alice
```

Voilà, the daemon should be good to go.
```bash
./ucafs
```

