/**
 * Contains function prototypes called from external programs (e.g. shell)
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

#pragma once


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
