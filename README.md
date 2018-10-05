# NEXUS

## Prerequisites

- Linux SGX - [https://github.com/intel/linux-sgx]().

- Fuse3 - https://github.com/libfuse/libfuse



## Up and Running with NeXUS

Lets begin by updating your package definitions and installing development tools.

```bash
sudo apt-get update
sudo apt-get install uuid-dev libgoogle-perftools-dev cscope build-essential make git libncurses5-dev libfuse-dev libcurl-devel libcurl4-openssl-dev libreadline-dev

```

Move to the nexus directory and check out

```bash
make -j$(nprocs)
```

To make sure all worked out, make sure: `echo $?` returns 0.

This creates the enclave and all static libraries in the `build` folder.



## Getting up and running !!!

The `shell` directory in the nexus code contains administrative utilities to create and manage volumes.

### 1. Initializing Private Keys

To create the private keys associated with the user, run:

```bash
./nexus_shell init
```

This creates a JSON file in `~/.nexus/.



### 2. Creating the volume instance

To create a volume, you need a volume config that specifies the datastore, metadata store and backend. In the shell directory, there is a sample configuration file called `volume_config.json`. The file should look something like this:

```json
{
    "metadata_store" : {
        "name" : "TWOLEVEL",
        "root_path" : "metadata"
    },

    "data_store" : {
        "name" : "TWOLEVEL",
        "root_path" : "files"
    },

    "backend" : {
        "name" : "SGX",
        "enclave_path": "/home/vagrant/nexus/build/nexus_enclave.signed.so"
    }

}
```

Make sure the `enclave_path` points to the build directory.



```bash
mkdir -p /tmp/vol /tmp/mnt 	# creates volume and mount directories
./nexus_shell create /tmp/vol ./volume_config.json
```

This will create the volume in /tmp/vol.



### 3. Starting the FUSE-based volume

On creating the volume, Nexus creates a ".nexus_volume.conf" file in the volume root directory. You have to change the datastore entry name to use "FUSE". Edit the file to look like this.

```json
{
	"metadata_store": {
		"name": "TWOLEVEL",
		"root_path": "metadata"
	},
	"data_store": {
		"name": "FUSE",
		"root_path": "files"
	},
	"backend": {
		"name": "SGX",
		"enclave_path": "/home/vagrant/nexus/build/nexus_enclave.signed.so"
	},
	"volume_uuid": "eYfhAVQ2RGmhrvnRoR21Ag..",
	"supernode_uuid": "W5oWYxv7sAaFcHGYxCpGPg.."
}
```



> N.B: This process will be changed to a more convenient solution soon :)



Now, go to `frontend_fuse/` and you can run the following

```bash
./nexus-fuse /tmp/repo /tmp/mnt
```



You can open a separate terminal window, and go to `/tmp/mnt
