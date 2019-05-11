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

static const char * WORDS_FILE = "google-10000-english.txt";
static size_t       WORDS_MAX  = 10000;


static FILE       * words_fileptr = NULL;


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
    int created = 0;

    if (argc < 1) {
        usage("attributes");
        return -1;
    }

    int count_arg = atoi(argv[0]);

    if (count_arg <= 0 || (count_arg > (int)WORDS_MAX)) {
        log_error("invalid count argument (%s)\n", argv[0]);
        return -1;
    }

    nexus_printf("Creating %d attributes...\n", count_arg);

    rewind(words_fileptr);


    for (; created < count_arg; created++) {
        char * word = read_line(words_fileptr);

        if (sgx_backend_abac_attribute_add(word, "user", mounted_volume)) {
            log_error("sgx_backend_abac_attribute_add() `%s` FAILED\n", word);
            nexus_free(word);
            goto out_err;
        }

        nexus_free(word);
    }

    nexus_printf("SUCCESS\n");

    return 0;

out_err:
    log_error("Created %d attributes\n", created);

    return -1;
}

static struct _cmd {
    char * name;
    int (*handler)(int argc, char ** argv);
    char * desc;
    char * usage;
} cmds[];

static struct _cmd cmds[] = { { "attributes", __attributes_filler, "fills in attributes", "<count>" },
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
            words_fileptr = fopen(WORDS_FILE, "r");

            if (words_fileptr == NULL) {
                log_error("could not open file (%s)\n", WORDS_FILE);
                goto out_err;
            }

            int ret = cmds[i].handler(argc - 2, &argv[3]);

            fclose(words_fileptr);

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
