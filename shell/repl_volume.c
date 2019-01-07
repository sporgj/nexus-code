#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <limits.h>

#include <nexus.h>
#include <nexus_backend.h>
#include <nexus_raw_file.h>
#include <nexus_util.h>
#include <nexus_log.h>
#include <nexus_volume.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <wordexp.h>

#include "handler.h"

#define MY_ARGV_SIZE 30

static int    my_argc               = 0;
static char * my_argv[MY_ARGV_SIZE] = { NULL };



static struct _cmd {
    char * name;
    int (*handler)(int argc, char ** argv);
    char * desc;
    char * usage;
} cmds[];


// lists the usage of a particular command, NULL to list all
static void usage(char * handle_cmd);



static struct nexus_volume * mounted_volume = NULL;


char *
__read_pubkey_file(char * pubkey_fpath, size_t * pubkey_len)
{
    char * filepath = NULL;
    char * pubkey_str = NULL;

    {
        wordexp_t pubkey_fpath_exp;

        wordexp(pubkey_fpath, &pubkey_fpath_exp, 0);

        filepath = strndup(pubkey_fpath_exp.we_wordv[0], PATH_MAX);

        wordfree(&pubkey_fpath_exp);
    }

    if (nexus_read_raw_file(filepath, (uint8_t **)&pubkey_str, pubkey_len)) {
        log_error("could not read file (%s)\n", filepath);
        nexus_free(filepath);
        return NULL;
    }

    nexus_free(filepath);

    return pubkey_str;
}

static int
handle_user_list(int argc, char ** argv)
{
    return nexus_backend_user_list(mounted_volume);
}

static int
handle_user_add(int argc, char ** argv)
{
    char * username     = argv[0];
    char * pubkey_fpath = argv[1];

    char * pubkey_str = NULL;
    size_t pubkey_len = 0;

    int ret = -1;


    if (argc < 2) {
        usage("user_add");
        return -1;
    }

    pubkey_str = __read_pubkey_file(pubkey_fpath, &pubkey_len);

    if (pubkey_str == NULL) {
        return -1;
    }

    ret = nexus_backend_user_add(mounted_volume, username, pubkey_str);

    nexus_free(pubkey_str);

    if (ret != 0) {
        log_error("nexus_backend_user_add FAILED\n");
        return -1;
    }

    return 0;
}

static int
handle_user_delname(int argc, char ** argv)
{
    char * username     = argv[0];

    if (argc < 1) {
        usage("user_delname");
        return -1;
    }

    return nexus_backend_user_delname(mounted_volume, username);
}


static int
handle_user_delkey(int argc, char ** argv)
{
    char * pubkey_fpath = argv[0];
    char * pubkey_str   = NULL;
    size_t pubkey_len   = 0;

    int ret = -1;


    if (argc < 1) {
        usage("user_delkey");
        return -1;
    }

    pubkey_str = __read_pubkey_file(pubkey_fpath, &pubkey_len);

    if (pubkey_str == NULL) {
        return -1;
    }

    ret = nexus_backend_user_delkey(mounted_volume, pubkey_str);

    nexus_free(pubkey_str);

    return ret;
}


static int
handle_user_findname(int argc, char ** argv)
{
    char * username     = argv[0];

    if (argc < 1) {
        usage("user_findname");
        return -1;
    }

    return nexus_backend_user_findname(mounted_volume, username);
}


static int
handle_user_findkey(int argc, char ** argv)
{
    char * pubkey_fpath = argv[0];
    char * pubkey_str   = NULL;
    size_t pubkey_len   = 0;

    int ret = -1;


    if (argc < 1) {
        usage("user_findkey");
        return -1;
    }

    pubkey_str = __read_pubkey_file(pubkey_fpath, &pubkey_len);

    if (pubkey_str == NULL) {
        return -1;
    }

    ret = nexus_backend_user_findkey(mounted_volume, pubkey_str);

    nexus_free(pubkey_str);

    return ret;
}


/////////

static int
handle_fs_create(int argc, char ** argv)
{
    char * filepath = NULL;

    if (argc < 1) {
        usage("fs_touch");
        return -1;
    }

    int ret = -1;


    filepath = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_create(mounted_volume, filepath, NEXUS_REG);

    nexus_free(filepath);

    return ret;
}

static int
handle_fs_remove(int argc, char ** argv)
{
    char * filepath = NULL;

    if (argc < 1) {
        usage("fs_remove");
        return -1;
    }

    int ret = -1;


    filepath = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_remove(mounted_volume, filepath);

    nexus_free(filepath);

    return ret;
}

static int
handle_fs_mkdir(int argc, char ** argv)
{
    char * dirpath = NULL;

    if (argc < 1) {
        usage("fs_mkdir");
        return -1;
    }

    int ret = -1;


    dirpath = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_create(mounted_volume, dirpath, NEXUS_DIR);

    nexus_free(dirpath);

    return ret;
}

static int
handle_fs_ls(int argc, char ** argv)
{
    char * dirpath = NULL;

    if (argc < 1) {
        usage("fs_ls");
        return -1;
    }

    int ret = -1;


    dirpath = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_ls(mounted_volume, dirpath);

    nexus_free(dirpath);

    return ret;
}

static int
handle_fs_fstat(int argc, char ** argv)
{
    char * path = NULL;

    if (argc < 1) {
        usage("fs_fstat");
        return -1;
    }

    int ret = -1;


    path = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_stat(mounted_volume, path, NEXUS_STAT_FILE);

    nexus_free(path);

    return ret;
}

static int
handle_fs_lstat(int argc, char ** argv)
{
    char * path = NULL;

    if (argc < 1) {
        usage("fs_lstat");
        return -1;
    }

    int ret = -1;


    path = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_stat(mounted_volume, path, NEXUS_STAT_LINK);

    nexus_free(path);

    return ret;
}

static int
handle_fs_getattr(int argc, char ** argv)
{
    char * path = NULL;

    if (argc < 1) {
        usage("fs_getattr");
        return -1;
    }

    int ret = -1;


    path = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_getattr(mounted_volume, path);

    nexus_free(path);

    return ret;
}

static int
handle_fs_symlink(int argc, char ** argv)
{
    char * path = NULL;
    char * target = NULL;

    if (argc < 2) {
        usage("fs_symlink");
        return -1;
    }

    int ret = -1;


    path = strndup(argv[0], NEXUS_PATH_MAX);
    target = strndup(argv[1], NEXUS_PATH_MAX);

    ret = __fs_symlink(mounted_volume, path, target);

    nexus_free(path);
    nexus_free(target);

    return ret;
}

static int
handle_fs_readlink(int argc, char ** argv)
{
    char * path = NULL;

    if (argc < 1) {
        usage("fs_readlink");
        return -1;
    }

    int ret = -1;


    path = strndup(argv[0], NEXUS_PATH_MAX);

    ret = __fs_readlink(mounted_volume, path);

    nexus_free(path);

    return ret;
}

static int
handle_fs_hardlink(int argc, char ** argv)
{
    char * link_filepath = NULL;
    char * target_filepath = NULL;

    if (argc < 2) {
        usage("fs_hardlink");
        return -1;
    }

    int ret = -1;


    link_filepath = strndup(argv[0], NEXUS_PATH_MAX);
    target_filepath = strndup(argv[1], NEXUS_PATH_MAX);

    ret = __fs_hardlink(mounted_volume, link_filepath, target_filepath);

    nexus_free(link_filepath);
    nexus_free(target_filepath);

    return ret;
}

static int
handle_fs_rename(int argc, char ** argv)
{
    char * src_path = NULL;
    char * dst_path = NULL;

    if (argc < 2) {
        usage("fs_rename");
        return -1;
    }

    int ret = -1;


    src_path = strndup(argv[0], NEXUS_PATH_MAX);
    dst_path = strndup(argv[1], NEXUS_PATH_MAX);

    ret = __fs_rename(mounted_volume, src_path, dst_path);

    nexus_free(src_path);
    nexus_free(dst_path);

    return ret;
}

static int
handle_fs_truncate(int argc, char ** argv)
{
    char * tmp      = NULL;
    char * filepath = NULL;
    size_t filesize = 0;

    if (argc < 2) {
        usage("fs_rename");
        return -1;
    }

    int ret = -1;


    filepath = strndup(argv[0], NEXUS_PATH_MAX);
    filesize = strtoul(argv[1], &tmp, 10);

    if (filesize == ULONG_MAX) {
        nexus_free(filepath);
        log_error("could not parse file size arg (%s)\n", argv[1]);
        return -1;
    }

    ret = __fs_truncate(mounted_volume, filepath, filesize);

    nexus_free(filepath);

    return ret;
}

/////////

static int
split_string_to_my_argv(char * parm_chars)
{
    int pos   = 0;
    int index = 0;
    int len   = strnlen(parm_chars, 1024);

    bool in_single_quote = false;
    bool in_double_quote = false;



    memset(my_argv, 0, sizeof(my_argv));
    my_argc = 0;


    for (; (parm_chars[index] == ' ' && index < len); index++) {

    }

    my_argv[0] = (parm_chars + index);
    pos        = 1;


    for (; index < len; index++)
    {
        if (parm_chars[index] == '"' && !in_single_quote)
        {
            in_double_quote = !in_double_quote;
            parm_chars[index] = '\0';
            my_argv[pos++] = (parm_chars + index + 1);
        }

        if (parm_chars[index] == '\'' && !in_double_quote)
        {
            in_single_quote = !in_single_quote;
            parm_chars[index] = '\0';
            my_argv[pos++] = (parm_chars + index + 1);
        }

        if (!in_single_quote && !in_double_quote && parm_chars[index] == ' ') {
            // if the previous element is also spacen, let's skip it
            if (index > 1 && parm_chars[index - 1] == ' ') {
                continue;
            }

            parm_chars[index] = '\0';
            my_argv[pos++] = (parm_chars + index + 1);
        }

        if (pos == MY_ARGV_SIZE) {
            log_error("too many arguments (count = %d)\n", pos);
            return -1;
        }
    }

    if (pos == 0 && my_argv[pos] != '\0') {
        pos = 1;
    }

    my_argc = pos;

    return 0;
}

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


static struct _cmd cmds[]
    = { { "user_list", handle_user_list, "List users in a volume", "" },
        { "user_add", handle_user_add, "Add user to the volume", "<username> <pubkey_file>" },
        { "user_delname", handle_user_delname, "Remove user by name", "<username>" },
        { "user_delkey", handle_user_delkey, "Remove user by pubkey", "<pubkey_file>" },
        { "user_findname", handle_user_findname, "Find user by name", "<username>" },
        { "user_findkey", handle_user_findkey, "Find user by pubkey", "<pubkey_file>" },

        { "fs_create", handle_fs_create, "Creates a new file", "<filepath>" },
        { "fs_remove", handle_fs_remove, "Deletes a new file", "<filepath>" },  // FIXME: change to "fs_delete"
        { "fs_mkdir", handle_fs_mkdir, "Creates a new directory", "<dirpath>" },
        { "fs_ls", handle_fs_ls, "Lists directory content", "<dirpath>" },
        { "fs_fstat", handle_fs_fstat, "Get file attributes", "<path>" },
        { "fs_lstat", handle_fs_lstat, "Get link attributes", "<path>" },
        { "fs_getattr", handle_fs_getattr, "get more stat attributes (including time)", "<path>" },
        { "fs_symlink", handle_fs_symlink, "Create symlink", "<path> <target>" },
        { "fs_readlink", handle_fs_readlink, "Read symlink target", "<path>" },
        { "fs_hardlink", handle_fs_hardlink, "Hardlink file", "<link_fpath> <target_fpath>" },
        { "fs_rename", handle_fs_rename, "Rename file", "<from_path> <to_path>" },
        { "fs_truncate", handle_fs_truncate, "Truncate file", "<file_path>" },

        { "help", help, "Prints usage", "" },
        { 0, 0, 0, 0 } };

int
repl_volume_main(int argc, char ** argv)
{
    char * volume_path = NULL;
    char * line = NULL;

    if (argc < 2) {
        log_error("repl> must pass volume path\n");
        return -1;
    }

    volume_path = strndup(argv[1], PATH_MAX);

    mounted_volume = nexus_mount_volume(volume_path);

    if (mounted_volume == NULL) {
        printf("Error: could not mount nexus volume (%s)\n", volume_path);
        nexus_free(volume_path);
        return -1;
    }

    nexus_free(volume_path);

    do {
        int i = 0;

        line = readline("> ");

        if (line == NULL) {
            printf("\nexiting...\n");
            fflush(stdout);
            return 0;
        }

        if (split_string_to_my_argv(line)) {
            return -1;
        }

        while (cmds[i].name) {

            if (strncmp(cmds[i].name, my_argv[0], 1024) == 0) {
                int ret = cmds[i].handler(my_argc - 1, &my_argv[1]);

                if (ret) {
                    printf("command failed\n");
                }
            }

            i++;
        }

        free(line);
    } while (true);
}
