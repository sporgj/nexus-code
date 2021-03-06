/**
 * Contains function prototypes called from external programs (e.g. shell)
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include <nexus_volume.h>

int
sgx_backend_print_telemetry(struct nexus_volume * volume);

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
sgx_backend_abac_attribute_add_bulk(char                * list_of_strings_by_newline,
                                    size_t                number_of_lines,
                                    struct nexus_volume * volume);

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


/// policy management

int
sgx_backend_abac_policy_add_bulk(char                * list_of_strings_by_newline,
                                 size_t                number_of_lines,
                                 struct nexus_volume * volume);

int
sgx_backend_abac_policy_add(char                * policy_string,
                            struct nexus_uuid   * uuid,
                            struct nexus_volume * volume);

int
sgx_backend_abac_policy_del(struct nexus_uuid * uuid, struct nexus_volume * volume);

int
sgx_backend_abac_policy_del_first(struct nexus_volume * volume);

int
sgx_backend_abac_policy_ls(struct nexus_volume * volume);

int
sgx_backend_abac_print_facts(struct nexus_volume * volume);

int
sgx_backend_abac_print_rules(struct nexus_volume * volume);

int
sgx_backend_abac_clear_facts(struct nexus_volume * volume);

int
sgx_backend_abac_clear_rules(struct nexus_volume * volume);

int
sgx_backend_abac_object_auditor(char * path, struct nexus_volume * volume);


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
