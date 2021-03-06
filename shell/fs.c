/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <nexus.h>
#include <nexus_config.h>
#include <nexus_fs.h>
#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_volume.h>

static int cmd_line_user_key = 0;

/*
 * This modifies argv in place moving all the nexus options to the beginning,
 * The return value is the number of options we capture as nexus options.
 * Further option processing can happen using argv and the return value as the offset at which to
 * start searching
 */
static int
__parse_nexus_options(int argc, char ** argv)
{
    int  opt_index = 0;
    int  used_opts = 0;
    char c         = 0;

    static struct option long_options[]
        = { { "user_key", required_argument, &cmd_line_user_key, 1 }, /* 0 */
            { 0, 0, 0, 0 } };

    while ((c = getopt_long_only(argc, argv, "h", long_options, &opt_index)) != -1) {

        switch (c) {
        case 0:
            switch (opt_index) {
            case 0:
                nexus_config.user_key_path = optarg;
                used_opts += 2;
                break;

            default:
                return -1;
            }
            break;
        case 'h':
        case '?':
        default:
            return -1;
        }
    }

    return used_opts;
}

static void
create_file_usage()
{
    printf("create_file: create a file at a volume path\n\n"
           "Usage: create_file <volume> <path-in-volume>\n");

    return;
}


static void
print_stat_info(const char * path, struct nexus_stat * nexus_stat)
{
    char * nexus_name = NULL;
    char * file_type = NULL;

    switch (nexus_stat->type) {
    case NEXUS_DIR:
        file_type = "DIR";
        break;
    case NEXUS_LNK:
        file_type = "LNK";
        break;
    default:
        file_type = "REG";
    }

    if (nexus_stat->link_type == NEXUS_LNK) {
        file_type  = "LNK";
        nexus_name = nexus_uuid_to_hex(&nexus_stat->link_uuid);
    } else {
        nexus_name = nexus_uuid_to_hex(&nexus_stat->uuid);
    }

    printf(" %s -> [%s] %s", path, file_type, nexus_name);

    if (nexus_stat->type == NEXUS_REG) {
        printf(". filesize=%zu", nexus_stat->filesize);
    } else if (nexus_stat->type == NEXUS_DIR) {
        printf(". dirsize=%zu", nexus_stat->filesize);
    }

    printf("\n");

    nexus_free(nexus_name);
}

static void
print_lookup_info(const char * path, struct nexus_fs_lookup * lookup_info)
{
    char * nexus_name = nexus_uuid_to_hex(&lookup_info->uuid);
    char * file_type = NULL;

    switch (lookup_info->type) {
    case NEXUS_DIR:
        file_type = "DIR";
        break;
    case NEXUS_LNK:
        file_type = "LNK";
        break;
    default:
        file_type = "REG";
    }

    printf(" %s -> [%s] %s\n", path, file_type, nexus_name);

    nexus_free(nexus_name);
}

#if 0
static void
print_attrs_info(const char * path, struct nexus_fs_attr * attrs)
{
    struct stat * st = &attrs->posix_stat;

    print_stat_info(path, &attrs->stat_info);

    printf("\t size: %zu, access time: %zu, mod time: %zu\n", st->st_size, st->st_atime, st->st_mtime);
}
#endif

int
__fs_stat(struct nexus_volume * vol, const char * path, nexus_stat_flags_t stat_flags)
{
    struct nexus_stat nexus_stat;

    if (nexus_fs_stat(vol, (char *)path, stat_flags, &nexus_stat)) {
        log_error("stat %s FAILED\n", path);
        return -1;
    }

    print_stat_info(path, &nexus_stat);

    return 0;
}

int
__fs_lookup(struct nexus_volume * vol, const char * path)
{
    char * dirpath  = NULL;
    char * filename = NULL;

    struct nexus_fs_lookup lookup_info;


    nexus_splitpath(path, &dirpath, &filename);

    if (nexus_fs_lookup(vol, dirpath, filename, &lookup_info)) {
        log_error("lookup %s FAILED\n", path);

        nexus_free(dirpath);
        nexus_free(filename);
        return -1;
    }

    print_lookup_info(path, &lookup_info);

    nexus_free(dirpath);
    nexus_free(filename);

    return 0;
}

int
__fs_getattr(struct nexus_volume * vol, char * path)
{
    log_error("function not implemented\n");

    return -1;

#if 0
    struct nexus_fs_attr attrs;

    if (nexus_fs_getattr(vol, path, &attrs)) {
        log_error("getattr %s FAILED\n", path);
        return -1;
    }

    print_attrs_info(path, &attrs);

    return 0;
#endif
}

int
__fs_create(struct nexus_volume * vol, const char * path, nexus_dirent_type_t type)
{
    char * dirpath  = NULL;
    char * filename = NULL;

    struct nexus_uuid uuid;

    int ret = -1;

    nexus_splitpath(path, &dirpath, &filename);

    ret = nexus_fs_create(vol, dirpath, filename, type, &uuid);

    nexus_free(dirpath);
    nexus_free(filename);

    if (ret != 0) {
        log_error("creating %s FAILED\n", path);
        return -1;
    }


    {
        char * nexus_name = nexus_uuid_to_hex(&uuid);
        printf(" .created %s -> %s\n", path, nexus_name);
        fflush(stdout);
        nexus_free(nexus_name);
    }

    return 0;
}

int
__fs_remove(struct nexus_volume * vol, const char * path)
{
    char * dirpath  = NULL;
    char * filename = NULL;

    struct nexus_fs_lookup lookup_info = { 0 };


    bool should_remove = false;


    nexus_splitpath(path, &dirpath, &filename);

    int ret = nexus_fs_remove(vol, dirpath, filename, &lookup_info, &should_remove);

    nexus_free(dirpath);
    nexus_free(filename);

    if (ret != 0) {
        log_error("removing %s FAILED\n", path);
        return -1;
    }

    printf(" .remove (rm=%d):: ", (int)should_remove);

    print_lookup_info(path, &lookup_info);


    return 0;

}

int
__fs_rename(struct nexus_volume * vol, const char * from_path, const char * to_path)
{
    char * from_dirpath  = NULL;
    char * from_filename = NULL;
    char * to_dirpath    = NULL;
    char * to_filename   = NULL;

    struct nexus_uuid uuid1;
    struct nexus_fs_lookup lookup_info;

    bool should_remove = false;

    int ret = -1;

    nexus_splitpath(from_path, &from_dirpath, &from_filename);
    nexus_splitpath(to_path, &to_dirpath, &to_filename);

    ret = nexus_fs_rename(vol,
                          from_dirpath,
                          from_filename,
                          to_dirpath,
                          to_filename,
                          &uuid1,
                          &lookup_info,
                          &should_remove);

    if (ret != 0) {
        log_error("rename operation\n");
        goto out;
    }

    {
        char * nexus_name1   = nexus_uuid_to_hex(&uuid1);
        char * nexus_name2   = nexus_uuid_to_hex(&lookup_info.uuid);

        printf(" .rename %s/%s [%s] -> %s/%s [%s] {rm=%d}\n",
                from_dirpath,
                from_filename,
                nexus_name1,
                to_dirpath,
                to_filename,
                nexus_name2,
                (int)should_remove);

        nexus_free(nexus_name1);
        nexus_free(nexus_name2);

        fflush(stdout);
    }

    ret = 0;
out:
    nexus_free(from_dirpath);
    nexus_free(from_filename);
    nexus_free(to_dirpath);
    nexus_free(to_filename);

    return ret;
}


static void
print_dirent_entry(struct nexus_dirent * dirent)
{
    char * type_str = "FILE";

    if (dirent->type == NEXUS_DIR) {
        type_str = "DIR";
    } else if (dirent->type == NEXUS_LNK) {
        type_str = "LINK";
    }

    printf("%26s [%s]\n", dirent->name, type_str);
}

int
__fs_ls(struct nexus_volume * vol, char * dirpath)
{
    size_t result_count   = 0;
    size_t directory_size = 0;
    size_t offset         = 0;

    size_t dirent_buffer_count = 50;
    size_t dirent_buffer_total = 0;

    struct nexus_dirent * dirent_buffer_array = NULL;


    dirent_buffer_total = dirent_buffer_count * sizeof(struct nexus_dirent);
    dirent_buffer_array = nexus_malloc(dirent_buffer_total);

    do {
        if (nexus_fs_readdir(vol,
                             dirpath,
                             dirent_buffer_array,
                             dirent_buffer_count,
                             offset,
                             &result_count,
                             &directory_size)) {
            log_error("nexus_fs_readdir FAILED\n");
            nexus_free(dirent_buffer_array);
            return -1;
        }

        if (offset == 0) {
            printf("Directory size: %zu\n", directory_size);
            printf("==========================\n");
        }

        for (size_t i = 0; i < result_count; i++) {
            print_dirent_entry(&dirent_buffer_array[i]);
        }

        fflush(stdout);

        offset += result_count;
    } while (offset < directory_size);


    nexus_free(dirent_buffer_array);

    return 0;
}

int
__fs_symlink(struct nexus_volume * vol, char * path, char * target)
{
    char * dirpath = NULL;
    char * filename = NULL;

    struct nexus_stat stat_info;

    int ret = -1;


    nexus_splitpath(path, &dirpath, &filename);

    ret = nexus_fs_symlink(vol, dirpath, filename, target, &stat_info);

    if (ret != 0) {
        log_error("symlink %s/%s -> %s FAILED\n", dirpath, filename, target);

        nexus_free(dirpath);
        nexus_free(filename);

        return -1;
    }


    {
        char * nexus_name = nexus_uuid_to_hex(&stat_info.uuid);
        printf(" .symlink %s -> %s\n", path, nexus_name);
        nexus_free(nexus_name);
    }

    nexus_free(dirpath);
    nexus_free(filename);

    return 0;
}

int
__fs_readlink(struct nexus_volume * vol, char * path)
{
    char * dirpath = NULL;
    char * filename = NULL;

    char * target = NULL;

    int ret = -1;


    nexus_splitpath(path, &dirpath, &filename);

    ret = nexus_fs_readlink(vol, dirpath, filename, &target);

    if (ret != 0) {
        log_error("readlink %s FAILED\n", path);

        nexus_free(dirpath);
        nexus_free(filename);
        return -1;
    }

    printf(" .readlink %s -> %s\n", path, target);

    nexus_free(dirpath);
    nexus_free(filename);
    nexus_free(target);

    return 0;
}

int
__fs_hardlink(struct nexus_volume * vol, char * link_filepath, char * target_filepath)
{
    char * link_dirpath = NULL;
    char * link_filename = NULL;
    char * target_dirpath = NULL;
    char * target_filename = NULL;

    struct nexus_uuid uuid;

    int ret = -1;


    nexus_splitpath(link_filepath, &link_dirpath, &link_filename);
    nexus_splitpath(target_filepath, &target_dirpath, &target_filename);

    ret = nexus_fs_hardlink(vol, link_dirpath, link_filename, target_dirpath, target_filename, &uuid);

    if (ret != 0) {
        log_error("nexus_fs_hardlink FAILED\n");
        goto out_err;
    }

    {
        char * nexus_name = nexus_uuid_to_hex(&uuid);
        printf(" .hardlink %s -> %s [%s]\n", link_filepath, target_filepath, nexus_name);
        nexus_free(nexus_name);
    }

    ret = 0;
out_err:
    nexus_free(link_dirpath);
    nexus_free(link_filename);
    nexus_free(target_dirpath);
    nexus_free(target_filename);

    return ret;
}

int
__fs_truncate(struct nexus_volume * vol, char * filepath, size_t filesize)
{
    struct nexus_stat nexus_stat;

    if (nexus_fs_truncate(vol, filepath, filesize, &nexus_stat)) {
        log_error("nexus_fs_setattr FAILED\n");
        return -1;
    }

    {
        char * nexus_name = nexus_uuid_to_hex(&nexus_stat.uuid);

        printf(".truncate %s -> %s [size = %zu]\n", filepath, nexus_name, filesize);

        nexus_free(nexus_name);
    }

    return 0;
}

int
create_file_main(int argc, char ** argv)
{
    struct nexus_volume * vol = NULL;

    char * volume_path = NULL;
    char * file_path   = NULL;

    int used_opts = 0;
    int ret       = 0;

    used_opts = __parse_nexus_options(argc, argv);

    if (used_opts == -1) {
        create_file_usage();
        return -1;
    }

    /* At this point we should just have the volume path in ARGV */

    if ((argc - used_opts) != 3) {
        create_file_usage();
        return -1;
    }

    volume_path = argv[used_opts + 1];
    file_path   = argv[used_opts + 2];

    vol = nexus_mount_volume(volume_path);

    if (vol == NULL) {
        printf("Error: could not mount nexus volume (%s)\n", volume_path);
        return -1;
    }

    (void)ret;

    if (__fs_create(vol, file_path, NEXUS_REG)) {
        return -1;
    }

    return 0;
}
