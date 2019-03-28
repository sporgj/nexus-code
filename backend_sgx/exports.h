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



// abac management stuff

int
sgx_backend_abac_attribute_add(char                * attribute_name,
                               char                * attribute_type,
                               struct nexus_volume * volume);

int
sgx_backend_abac_attribute_del(char * attribute_name, struct nexus_volume * volume);

int
sgx_backend_abac_attribute_ls(struct nexus_volume * volume);

int
sgx_backend_abac_user_grant(char                * username,
                            char                * attribute_name,
                            char                * attribute_val,
                            struct nexus_volume * volume);

int
sgx_backend_abac_user_revoke(char                * username,
                             char                * attribute_name,
                             struct nexus_volume * volume);

int
sgx_backend_abac_user_ls(char * username, struct nexus_volume * volume);

int
sgx_backend_abac_object_grant(char                * path,
                              char                * attribute_name,
                              char                * attribute_val,
                              struct nexus_volume * volume);

int
sgx_backend_abac_object_revoke(char                * path,
                               char                * attribute_name,
                               struct nexus_volume * volume);

int
sgx_backend_abac_object_ls(char * path, struct nexus_volume * volume);
