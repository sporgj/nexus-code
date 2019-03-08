/**
 * Contains function prototypes called from external programs (e.g. shell)
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include <nexus_volume.h>

int
sgx_backend_export_rootkey(char                * destination_path,
                           char                * other_instance_fpath,
                           struct nexus_volume * volume);

/**
 * Imports the rootkey from an exchange. Before callling this function, make sure
 * nexus_config.instance_path and nexus_config.enclave_path are initialized
 */
int
sgx_backend_import_rootkey(char * rk_exchange_path);


// batch mode commands

int
sgx_backend_batch_mode_start(struct nexus_volume * volume);

/** commits dirty buffers in batch mode */
int
sgx_backend_batch_mode_commit(struct nexus_volume * volume);

int
sgx_backend_batch_mode_finish(struct nexus_volume * volume);


int
sgx_backend_stat_uuid(struct nexus_volume  * volume,
                      struct nexus_uuid    * uuid,
                      struct nexus_fs_attr * attrs);


struct nexus_datastore *
sgx_backend_get_datastore(struct nexus_volume * volume, struct nexus_uuid * uuid);
