/**
 * Runs benchmarks with the ABAC stuff
 *
 * @author Judicael Djoko <jdjoko@cs.pitt.edu>
 */

#include <libnexus/nexus_log.h>
#include <libnexus/nexus_volume.h>
#include <libnexus/nexus_util.h>

#include <backend_sgx/exports.h>


static struct nexus_volume * mounted_volume;


static void
usage(char * handle_cmd);

static int
help(int argc, char ** argv);


static char *
read_line(FILE * fp)
{
    char * tmp_charptr = nexus_malloc(64);

    char * rv = fgets(tmp_charptr, 64, fp);

    if (rv == NULL) {
        perror("fgets");
        nexus_free(tmp_charptr);
        return NULL;
    }

    char * p_newline = strchr(rv, '\n');

    if (p_newline) {
        *p_newline = '\0';
    }

    return rv;
}

static int
__attributes_filler(int argc, char ** argv)
{
    size_t created = 0;

    if (argc < 1) {
        usage("attributes");
        return -1;
    }

    char * filepath = strndup(argv[0], PATH_MAX);

    FILE * file_ptr = fopen(filepath, "r");

    if (file_ptr == NULL) {
        log_error("could not open file %s\n", filepath);
        goto out_err;
    }

    while (feof(file_ptr) == false) {
        // <attr_name, attr_type>
        char * attribute_pair = read_line(file_ptr);
        if (attribute_pair == NULL) {
            break;
        }

        char * _name = strtok(attribute_pair, ",");
        char * _type = strtok(NULL, ",");

        if (sgx_backend_abac_attribute_add(_name, _type, mounted_volume)) {
            log_error("sgx_backend_abac_attribute_add() `%s` (%s) FAILED\n", _name, _type);
            nexus_free(attribute_pair);
            goto out_err;
        }

        nexus_free(attribute_pair);

        created += 1;
    }

    nexus_printf("CREATED ATTRIBUTES: %zu\n", created);

    fclose(file_ptr);
    nexus_free(filepath);

    return 0;
out_err:
    nexus_printf("CREATED ATTRIBUTES: %zu\n", created);

    fclose(file_ptr);
    nexus_free(filepath);

    return -1;
}


static int
__policies_filler(int argc, char ** argv)
{
    size_t added = 0;

    if (argc < 1) {
        usage("policies");
        return -1;
    }

    char * filepath = strndup(argv[0], PATH_MAX);

    FILE * file_ptr = fopen(filepath, "r");

    if (file_ptr == NULL) {
        log_error("could not open file %s\n", filepath);
        goto out_err;
    }

    while (feof(file_ptr) == false) {
        struct nexus_uuid uuid;

        char * policy_str = read_line(file_ptr);
        if (policy_str == NULL) {
            break;
        }

        if (sgx_backend_abac_policy_add(policy_str, &uuid, mounted_volume)) {
            nexus_free(policy_str);
            log_error("sgx_backend_abac_policy_add() FAILED\n");
            goto out_err;
        }

        nexus_free(policy_str);

        added += 1;
    }

    nexus_printf("ADDED POLICIES: %zu\n", added);

    fclose(file_ptr);
    nexus_free(filepath);

    return 0;
out_err:
    nexus_printf("ADDED POLICIES: %zu\n", added);

    fclose(file_ptr);
    nexus_free(filepath);

    return -1;
}


static struct _cmd {
    char * name;
    int (*handler)(int argc, char ** argv);
    char * desc;
    char * usage;
} cmds[];

static struct _cmd cmds[]
    = { { "attributes", __attributes_filler, "fills in attributes", "<count>" },
        { "policies", __policies_filler, "fills in policies", "<policy file>" },
        { "help", help, "Help menu", "" },
        { NULL, NULL, NULL, NULL } };

static void
usage(char * handle_cmd)
{
    int i = 0;

    while (cmds[i].name) {
        if (handle_cmd && strncmp(handle_cmd, cmds[i].name, strnlen(cmds[i].name, 1024)) != 0) {
            goto skip;
        }

        printf("%-5s -- %s\n", cmds[i].name, cmds[i].desc);
        printf("\t%s %s\n", cmds[i].name, cmds[i].usage);

skip:
        i++;
    }
}

static int
help(int argc, char ** argv)
{
    usage(NULL);
    return 0;
}

int
filler_volume_main(int argc, char ** argv)
{
    int i = 0;

    if (argc < 3) {
        log_error("must pass volume and sub command\n");
        return -1;
    }

    char * volume_path = strndup(argv[1], 1024);
    char * sub_command = argv[2];


    mounted_volume = nexus_mount_volume(volume_path);

    if (mounted_volume == NULL) {
        printf("Error: could not mount nexus volume (%s)\n", volume_path);
        nexus_free(volume_path);
        return -1;
    }

    nexus_free(volume_path);

    while (cmds[i].name) {
        if (strncmp(cmds[i].name, sub_command, 1024) == 0) {
            int ret = cmds[i].handler(argc - 2, &argv[3]);

            if (ret) {
                printf("command failed\n");
                goto out_err;
            }

            return 0;
        }

        i++;
    }

    log_error("command `%s` not found\n", sub_command);

out_err:
    return -1;
}
