/**
 * Runs benchmarks with the ABAC stuff
 *
 * @author Judicael Djoko <jdjoko@cs.pitt.edu>
 */

#include <libnexus/nexus_log.h>
#include <libnexus/nexus_volume.h>
#include <libnexus/nexus_util.h>
#include <libnexus/nexus_raw_file.h>

#include <backend_sgx/exports.h>


static struct nexus_volume * mounted_volume;


static void
usage(char * handle_cmd);

static int
help(int argc, char ** argv);


static size_t
count_lines (FILE * fp, size_t * p_file_size)
{
    size_t line_count = 0;
    size_t file_size  = 0;

    rewind(fp);

    for (char c = getc(fp); c != EOF; c = getc(fp)) {
        if (c == '\n') {
            line_count += 1;
        }

        file_size += 1;
    }

    rewind(fp);

    *p_file_size = file_size;

    return line_count;
}

static int
__attributes_filler(int argc, char ** argv)
{
    size_t    buflen = 0;
    uint8_t * buffer = NULL;

    if (argc < 1) {
        usage("attributes");
        return -1;
    }

    char * filepath  = strndup(argv[0], PATH_MAX);
    size_t file_size = 0;
    FILE * file_ptr  = fopen(filepath, "r");

    if (file_ptr == NULL) {
        log_error("could not open file %s\n", filepath);
        return -1;
    }

    if (sgx_backend_batch_mode_start(mounted_volume)) {
        log_error("sgx_backend_batch_mode_start() FAILED\n");
        goto out_err;
    }

    size_t line_count = count_lines(file_ptr, &file_size);

    if (__nexus_read_raw_file(file_ptr, file_size, &buffer, &buflen)) {
        log_error("__nexus_read_raw_file() FAILED\n");
        goto out_err;
    }

    nexus_printf("Adding %zu attributes\n", line_count);

    if (sgx_backend_abac_attribute_add_bulk((char *)buffer, line_count, mounted_volume)) {
        log_error("sgx_backend_abac_attribute_add_bulk() FAILED\n");
        goto out_err;
    }

    if (sgx_backend_batch_mode_finish(mounted_volume)) {
        log_error("sgx_backend_batch_mode_finish() FAILED\n");
        goto out_err;
    }

    nexus_free(buffer);
    fclose(file_ptr);
    nexus_free(filepath);

    return 0;
out_err:

    nexus_free(buffer);
    fclose(file_ptr);
    nexus_free(filepath);

    return -1;
}


static int
__policies_filler(int argc, char ** argv)
{
    size_t    buflen = 0;
    uint8_t * buffer = NULL;

    if (argc < 1) {
        usage("policies");
        return -1;
    }

    char * filepath = strndup(argv[0], PATH_MAX);
    size_t file_size = 0;
    FILE * file_ptr = fopen(filepath, "r");

    if (file_ptr == NULL) {
        log_error("could not open file %s\n", filepath);
        return -1;
    }

    if (sgx_backend_batch_mode_start(mounted_volume)) {
        log_error("sgx_backend_batch_mode_start() FAILED\n");
        goto out_err;
    }

    size_t line_count = count_lines(file_ptr, &file_size);

    if (__nexus_read_raw_file(file_ptr, file_size, &buffer, &buflen)) {
        log_error("__nexus_read_raw_file() FAILED\n");
        goto out_err;
    }

    nexus_printf("Adding %zu policies\n", line_count);

    if (sgx_backend_abac_policy_add_bulk((char *)buffer, line_count, mounted_volume)) {
        log_error("sgx_backend_abac_policy_add() FAILED\n");
        goto out_err;
    }

    if (sgx_backend_batch_mode_finish(mounted_volume)) {
        log_error("sgx_backend_batch_mode_finish() FAILED\n");
        goto out_err;
    }

    nexus_free(buffer);
    fclose(file_ptr);
    nexus_free(filepath);

    return 0;
out_err:
    nexus_free(buffer);
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
