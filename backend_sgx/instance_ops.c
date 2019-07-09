#include "internal.h"

struct nxs_instance * global_nxs_instance = NULL;


sgx_spid_t global_spid = {.id = { 0x31, 0xC1, 0xBA, 0xF1, 0x1F, 0x76, 0xEB, 0xA2,
                           0x43, 0x5E, 0x6A, 0x72, 0xCE, 0x30, 0xB2, 0x2F }};


static struct nxs_instance *
__create_instance(sgx_enclave_id_t enclave_id)
{
    struct nxs_instance * nxs_instance = NULL;

    struct ecdh_public_key owner_pubkey;

    uint8_t * owner_sealed_privkey = NULL;
    size_t    owner_sealed_privkey_len;

    sgx_quote_t * quote      = NULL;
    uint32_t      quote_size = 0;


    {
        sgx_target_info_t   target_info;
        sgx_epid_group_id_t epid_gid;
        sgx_report_t        report;

        int err = -1;
        int ret = -1;


        ret = sgx_init_quote(&target_info, &epid_gid);

        if (ret != SGX_SUCCESS) {
            printf("Error Initializing Quote\n");
            goto err;
        }

        err = ecall_new_instance(enclave_id,
                                 &ret,
                                 &target_info,
                                 &report,
                                 &owner_pubkey,
                                 &owner_sealed_privkey,
                                 &owner_sealed_privkey_len);

        if (err || ret) {
            log_error("ecall_new_instance FAILED, err=%x, ret=%d\n", err, ret);
            goto err;
        }

        quote = generate_quote(&report, &quote_size);

        if (quote == NULL) {
            log_error("generate_quote FAILED\n");
            goto err;
        }
    }

    nxs_instance = nexus_malloc(sizeof(struct nxs_instance));

    nxs_instance->quote          = quote;
    nxs_instance->quote_size     = quote_size;
    nxs_instance->sealed_privkey = owner_sealed_privkey;
    nxs_instance->privkey_size   = owner_sealed_privkey_len;

    memcpy(&nxs_instance->pubkey, &owner_pubkey, sizeof(struct ecdh_public_key));

    return nxs_instance;
err:
    if (quote) {
        nexus_free(quote);
    }

    if (owner_sealed_privkey) {
        nexus_free(owner_sealed_privkey);
    }

    return NULL;
}


int
nxs_load_instance(char * instance_fpath, sgx_enclave_id_t enclave_id)
{
    struct nxs_instance * new_instance = fetch_nxs_instance(instance_fpath);

    if (new_instance == NULL) {
        log_error("could not load: %s\n", instance_fpath);
        return -1;
    }

    {
        int err = -1;
        int ret = -1;

        err = ecall_mount_instance(enclave_id,
                                   &ret,
                                   &new_instance->pubkey,
                                   new_instance->sealed_privkey,
                                   new_instance->privkey_size);

        if (err || ret) {
            free_nxs_instance(new_instance);
            log_error("ecall_mount_instance FAILED, err=0x%x, ret=%d\n", err, ret);
            return -1;
        }
    }

    if (global_nxs_instance) {
        free_nxs_instance(global_nxs_instance);
    }

    global_nxs_instance = new_instance;

    return 0;
}



int
nxs_create_instance(char * enclave_path, char * instance_fpath)
{
    struct nxs_instance * instance = NULL;

    sgx_enclave_id_t enclave_id;


    if (main_create_enclave(enclave_path, &enclave_id)) {
        log_error("could not create the enclave (%s)\n", enclave_path);
        return -1;
    }


    instance = __create_instance(enclave_id);

    if (instance == NULL) {
        log_error("could not create instance\n");
        goto err;
    }

    if (store_nxs_instance(instance, instance_fpath)) {
        log_error("could not serialize key file\n");
        goto err;
    }

    sgx_destroy_enclave(enclave_id);

    free_nxs_instance(instance);

    return 0;

err:
    sgx_destroy_enclave(enclave_id);

    free_nxs_instance(instance);

    return -1;
}


static struct rk_exchange *
create_rk_exchange(struct nxs_instance * other_instance, sgx_enclave_id_t enclave_id)
{
    struct rk_exchange * message = nexus_malloc(sizeof(struct rk_exchange));

    int err = -1;
    int ret = -1;

    err = ecall_exchange_rootkey(enclave_id,
                                 &ret,
                                 other_instance->quote,
                                 &other_instance->pubkey,
                                 &message->ephemeral_pubkey,
                                 &message->nonce,
                                 &message->ciphertext,
                                 &message->ciphertext_len);

    if (err || ret) {
        nexus_free(message);

        log_error("ecall_exchange_rootkey FAILED\n");
        return NULL;
    }

    return message;
}


int
sgx_backend_export_rootkey(char                * destination_path,
                           char                * other_instance_fpath,
                           struct nexus_volume * volume)
{
    struct nxs_instance * other_instance = NULL;

    struct sgx_backend  * sgx_backend    = (struct sgx_backend *)volume->private_data;


    if (global_nxs_instance == NULL) {
        log_error("no instance mounted\n");
        return -1;
    }

    other_instance = fetch_nxs_instance(other_instance_fpath);

    if (other_instance == NULL) {
        log_error("could not load: %s\n", other_instance_fpath);
        return -1;
    }

    if (validate_quote(other_instance->quote, other_instance->quote_size)) {
        log_error("validate_quote() FAILED\n");
        goto err;
    }


    // generate the exchange message and write it
    {
        struct rk_exchange * sealed_rk_message =  NULL;

        sealed_rk_message = create_rk_exchange(other_instance, sgx_backend->enclave_id);

        if (sealed_rk_message == NULL) {
            log_error("create_rk_exchange FAILED\n");
            goto err;
        }

        nexus_uuid_copy(&volume->vol_uuid, &sealed_rk_message->volume_uuid);

        if (store_xchg_message(destination_path, sealed_rk_message)) {
            free_xchg_message(sealed_rk_message);
            log_error("could not store xchg message: %s", destination_path);
            goto err;
        }
    }


    free_nxs_instance(other_instance);

    return 0;
err:
    free_nxs_instance(other_instance);

    return -1;
}




static int
extract_rk_secret(struct rk_exchange      * message,
                  sgx_enclave_id_t          enclave_id,
                  struct nexus_key_buffer * keybuf)
{
    int err = -1;
    int ret = -1;

    err = ecall_extract_rootkey(enclave_id,
                                &ret,
                                &message->ephemeral_pubkey,
                                message->ciphertext,
                                message->ciphertext_len,
                                &message->nonce,
                                keybuf);

    if (err || ret) {
        log_error("ecall_extract_rootkey FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}


static int
__add_rootkey_volume(struct nexus_uuid * volume_uuid, struct nexus_key_buffer * keybuf)
{
    struct nexus_key sealed_volkey;

    memset(&sealed_volkey, 0, sizeof(struct nexus_key));

    if (key_buffer_derive(keybuf, &sealed_volkey)) {
        log_error("key_buffer_derive() FAILED\n");
        return -1;
    }

    if (nexus_del_volume_key(volume_uuid)) {
        log_error("nexus_del_volume_key() FAILED\n");
        return -1;
    }

    if (nexus_add_volume_key(volume_uuid, &sealed_volkey)) {
        nexus_free_key(&sealed_volkey);
        log_error("nexus_add_volume_key() FAILED\n");
        return -1;
    }

    nexus_free_key(&sealed_volkey);

    return 0;
}

int
sgx_backend_import_rootkey(char * rk_exchange_path)
{
    struct nexus_key_buffer rootkey_keybuf;

    struct rk_exchange * rk_exchange_msg = NULL;

    sgx_enclave_id_t enclave_id;



    if (main_create_enclave(nexus_config.enclave_path, &enclave_id)) {
        log_error("could not create the enclave (%s)\n", nexus_config.enclave_path);
        return -1;
    }



    key_buffer_init(&rootkey_keybuf);

    if (nxs_load_instance(nexus_config.instance_path, enclave_id)) {
        log_error("no instance mounted\n");
        goto err;
    }


    rk_exchange_msg = fetch_xchg_message(rk_exchange_path);

    if (rk_exchange_msg == NULL) {
        log_error("could not read xchg secret (%s)\n", rk_exchange_path);
        goto err;
    }


    if (extract_rk_secret(rk_exchange_msg, enclave_id, &rootkey_keybuf)) {
        log_error("extract_rk_secret() FAILED\n");
        goto err;
    }


    if (__add_rootkey_volume(&rk_exchange_msg->volume_uuid, &rootkey_keybuf)) {
        free_xchg_message(rk_exchange_msg);
        log_error("could not add sealed rootkey to volume\n");
        goto err;
    }


    key_buffer_free(&rootkey_keybuf);

    free_xchg_message(rk_exchange_msg);

    sgx_destroy_enclave(enclave_id);

    return 0;
err:
    key_buffer_free(&rootkey_keybuf);

    if (rk_exchange_msg) {
        free_xchg_message(rk_exchange_msg);
    }

    sgx_destroy_enclave(enclave_id);

    return -1;
}


// https://gist.github.com/dgoguerra/7194777
static const char *
human_size(uint64_t bytes)
{
    char * suffix[] = { "B", "KB", "MB", "GB", "TB" };
    char   length   = sizeof(suffix) / sizeof(suffix[0]);

    int    i        = 0;
    double dblBytes = bytes;

    if (bytes > 1024) {
        for (i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024)
            dblBytes = bytes / 1024.0;
    }

    static char output[200];
    sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
    return output;
}

int
sgx_backend_print_telemetry(struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    struct nxs_telemetry telemetry;

    int ret = -1;
    int err = ecall_export_telemetry(backend->enclave_id, &ret, &telemetry);

    if (ret || err) {
        log_error("ecall_export_telemetry() ret=%d, err=%d\n", ret, err);
        return -1;
    }

    // perform the printing
    {
        printf("TELEMETRY INFO\n---\n");

        printf("Allocated memory: %s\n", human_size(telemetry.total_allocated_bytes));
        printf("Lua memory: %zu KB\n", telemetry.lua_memory_kilobytes);
        printf("User Table: %zu user%c [%s]\n",
               telemetry.user_table_count,
               (telemetry.user_table_count == 1 ? '' : 's'),
               human_size(telemetry.user_table_bytes));
        printf("Attribute Space: %zu attributes [%s]\n",
               telemetry.attribute_space_count,
               human_size(telemetry.attribute_space_bytes));
        printf("Policy Store: %zu policies [%s]\n",
               telemetry.policy_store_count,
               human_size(telemetry.policy_store_bytes));
        printf("Rules count: %zu\n", telemetry.asserted_rules_count);
        printf("Facts count: %zu\n", telemetry.asserted_facts_count);
    }

    return 0;
}
