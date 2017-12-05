#include "ucafs_tests.h"

const char * dnode_file = "./repo/dnode-test";

#if 0
#define N 6
TEST(DIRNODE, test1)
{
    ucafs_entry_type atype;
    uc_dirnode_t * dirnode = dirnode_new();
    shadow_t * shadows[N];
    sds fname, dnode_fname = sdsnew(dnode_file);
    const char * name;

    /* initialize the enclave */
    if (ucafs_init_enclave()) {
        return;
    }

    for (size_t x = 0; x < N; x++) {
        fname = string_and_number("test", x);

        shadows[x] = dirnode_add(dirnode, fname, UC_FILE, 0);

        sdsfree(fname);
    }

    ASSERT_TRUE(dirnode_write(dirnode, dnode_file));
    dirnode_free(dirnode);

    ASSERT_FALSE((dirnode = dirnode_from_file(dnode_fname)) == NULL) << "oops";

    for (size_t x = 0; x < N; x++) {
        name = dirnode_enc2raw(dirnode, shadows[x], UC_FILE, &atype);
        ASSERT_TRUE(name != NULL);
    }

    dirnode_free(dirnode);
    sdsfree(dnode_fname);
}

const char * fbox_file = "./repo/filebox-test";
TEST(FILEBOX, test1)
{
    uc_filebox_t * filebox1 = filebox_new();
    sds fpath = sdsnew(fbox_file);

    /* write the filebox to disk */
    filebox_set_size(filebox1, UCAFS_CHUNK_SIZE);
    ASSERT_TRUE(filebox_write(filebox1, fbox_file));

    /* read filebox in a separate variable */
    uc_filebox_t * filebox2 = filebox_from_file(fpath);
    ASSERT_NE(filebox2, nullptr);

    ASSERT_EQ(0, memcmp(&filebox1->header, &filebox2->header,
                        sizeof(filebox_header_t)));
}

#define TEST_REPEAT 10
#define FILEBOX_SIZE (3 * (size_t)(1 << 30)) // 3 GB
TEST(FILEBOX, test2)
{
    ASSERT_EQ(0, start_testbed()) << "Starting testbed failed";
    uc_filebox_t * filebox1 = filebox_new();
    sds fpath = sdsnew(fbox_file);

    filebox_set_size(filebox1, FILEBOX_SIZE);

    /* write it to disk */
    ASSERT_TRUE(filebox_write(filebox1, fbox_file));
    filebox_free(filebox1);

    /* now let's try to open and close it multiple times */
    for (size_t i = 0; i < TEST_REPEAT; i++) {
        uc_filebox_t * filebox2 = filebox_from_file(fbox_file);

        ASSERT_FALSE(filebox2 == NULL) << "oops, cannot work";

        filebox_free(filebox2);
    }
}

#endif

#define KB_FILE (size_t)(1 << 10)
#define MB_FILE (size_t)(1 << 20)
#define GB_FILE (size_t)(1 << 30)
#define PAGE_SIZE 4096
#define BUFFER_LEN PAGE_SIZE * 32

typedef struct {
    char bytes[32];
} sha256_buf_t;
const uint32_t file_sizes[]
    = { 10 * KB_FILE,  20,       5 * MB_FILE, 10 * MB_FILE,
        100 * MB_FILE, 512 * MB_FILE, 3 * GB_FILE, 0 };
char buf[4096];

TEST(FILEBOX, test3)
{
    uint32_t fsize = 1;
    int bytes_left, chunk_left, chunk_num = 0, nbytes, cmp;
    mbedtls_sha256_context _, *sha_ctx = &_;
    char * temp;
    const char * fname = "foo";
    FILE * fd = NULL;
    sha256_buf_t *write_sha = NULL, *read_sha = NULL;
    ASSERT_EQ(0, start_testbed()) << "Starting testbed failed";

    sds root_path = do_make_path(global_supernode_paths[0], UCAFS_WATCH_DIR);

    /* let's setup the test environment */
    sds filepath = do_make_path(root_path, fname);
    ASSERT_EQ(0, dirops_new(filepath, UC_DIR, &temp));


    /* allocate the global memory table */
    global_xfer_buflen = BUFFER_LEN;
    ASSERT_EQ(0, posix_memalign((void **)&global_xfer_addr, PAGE_SIZE,
                                global_xfer_buflen));

    /* iterate for each file size */
    for (size_t i = 0; fsize != 0; i++) {
        fsize = file_sizes[i];
        // calculate the number of chunks
        size_t nchunks = UCAFS_CHUNK_COUNT(fsize);

        uinfo("Running filesize: %zu, nchunks=%zu", (size_t)fsize, nchunks);

        /* allocate the sha256 array */
        write_sha = (sha256_buf_t *)calloc(sizeof(sha256_buf_t), nchunks);
        ASSERT_FALSE(write_sha == NULL) << "allocation failed";

        /* create a fetch request */
        xfer_rsp_t rsp;
        xfer_req_t req = {.op = UCAFS_STORE,
                          .xfer_size = fsize,
                          .offset = 0,
                          .file_size = (uint32_t)fsize };

        ASSERT_EQ(0, fetchstore_init(&req, filepath, &rsp))
            << "fetchstore init failed";

        mbedtls_sha256_init(sha_ctx);
        fd = fopen(filepath, "wb");

        /* prefill the buffer and start encrypting */
        bytes_left = fsize, chunk_left = MIN(bytes_left, UCAFS_CHUNK_SIZE),
        chunk_num = 0, nbytes;
        while (bytes_left > 0) {
            nbytes = MIN(bytes_left, global_xfer_buflen);

            // copy data into the buffer
            memset(global_xfer_addr, (char)i, nbytes);
            mbedtls_sha256_update(sha_ctx, global_xfer_addr, nbytes);

            /* run it */
            fetchstore_run(rsp.xfer_id, nbytes);

            /* write it to the file descriptor */
            fwrite(global_xfer_addr, 1, nbytes, fd);

            bytes_left -= nbytes;
            chunk_left -= nbytes;

            if (chunk_left == 0) {
                chunk_left = MIN(bytes_left, UCAFS_CHUNK_SIZE);

                mbedtls_sha256_finish(sha_ctx,
                                      (uint8_t *)&write_sha[chunk_num]);
                mbedtls_sha256_init(sha_ctx);
                chunk_num++;
            }
        }

        ASSERT_EQ(0, fetchstore_finish(rsp.xfer_id));
        fclose(fd);

        req.op = UCAFS_FETCH;
        ASSERT_EQ(0, fetchstore_init(&req, filepath, &rsp))
            << "fetchstore init failed";

        /* decrypt the contents */
        mbedtls_sha256_init(sha_ctx);

        fd = fopen(filepath, "rb");
        bytes_left = fsize, chunk_left = MIN(bytes_left, UCAFS_CHUNK_SIZE),
        chunk_num = 0, nbytes;
        sha256_buf_t sha_hash;

        /* change it to decrypt */
        while (bytes_left > 0) {
            nbytes = MIN(bytes_left, global_xfer_buflen);

            /* write it to the file descriptor */
            fread(global_xfer_addr, 1, nbytes, fd);

            /* run it */
            fetchstore_run(rsp.xfer_id, nbytes);
            mbedtls_sha256_update(sha_ctx, global_xfer_addr, nbytes);

            bytes_left -= nbytes;
            chunk_left -= nbytes;

            if (chunk_left == 0) {
                chunk_left = MIN(bytes_left, UCAFS_CHUNK_SIZE);

                mbedtls_sha256_finish(sha_ctx, (uint8_t *)&sha_hash);

                ASSERT_EQ(0, memcmp(&sha_hash, &write_sha[chunk_num],
                                    sizeof(sha256_buf_t)));

                mbedtls_sha256_init(sha_ctx);
                chunk_num++;
            }
        }

        /* now let's just read and write the file */
        /*write_file(fd, 0, fsize, write_sha);
        read_file(fd, 0, fsize, write_sha);*/

        free(write_sha);
        fclose(fd);
    }

    sdsfree(filepath);
    sdsfree(root_path);
}

#if 0
TEST(DIRNODE, test1)
{
    uc_dirnode_t * dirnode = dirnode_new();
    shadow_t *shdw1 = NULL, *shdw2;
    const char *fname = "test", *str1;
    char * temp1;
    ucafs_entry_type atype;

    /* 1 - adding entry to the dirnode */
    uinfo("adding %s to dirnode", fname);
    shdw1 = dirnode_add(dirnode, fname, UC_FILE);
    ASSERT_FALSE(shdw1 == NULL) << "dirnode_add returned NULL";

    log_info("dirnode_add: fname -> %s", (temp1 = filename_bin2str(shdw1)));

    /* 2 - converting shadow to real */
    uinfo("dirnode_enc2raw");
    str1 = dirnode_enc2raw(dirnode, shdw1, atype, &atype);
    ASSERT_FALSE(str1 == NULL) << "dirnode_enc2raw returned NULL";

    ASSERT_STREQ(fname, str1) << "oops";

    /* 3 - raw to shadow */
    uinfo("dirnode_raw2enc");
    shdw2 = (shadow_t *)dirnode_raw2enc(dirnode, fname, atype, &atype);
    ASSERT_EQ(0, memcmp(shdw1, shdw2, sizeof(shadow_t)));

    uinfo("dirnode_rm");
    shdw2 = (shadow_t *)dirnode_rm(dirnode, fname, atype, &atype, NULL);
    ASSERT_EQ(0, memcmp(shdw1, shdw2, sizeof(shadow_t)));

    dirnode_free(dirnode);

    free(shdw1);
    free(shdw2);
    free(temp1);
}

TEST(DIRNODE, test2)
{
    uc_dirnode_t *dirnode = dirnode_new(), *dirnode2;
    shadow_t *shdw1 = NULL, *shdw2;
    const char *tpl = "file%d.txt", *fname = "dirnode.txt";
    char buffer[30];

    ASSERT_EQ(0, ucafs_init_enclave()) << "Enclave failed: "
                                       << ENCLAVE_FILENAME;

    for (size_t i = 1; i < 6; i++) {
        snprintf(buffer, sizeof(buffer), tpl, i);

        shdw1 = dirnode_add(dirnode, buffer, UC_FILE);
        ASSERT_FALSE(shdw1 == NULL) << "dirnode_add (" << buffer << ") FAILED";

        free(shdw1);
    }

    ASSERT_TRUE(dirnode_write(dirnode, fname));

    dirnode2 = dirnode_from_file(sdsnew(fname));
    ASSERT_FALSE(dirnode2 == NULL) << "dirnode_from_file returned NULL";

    dirnode_free(dirnode);
}

TEST(DIRNODE, test3)
{
    uc_dirnode_t *dirnode1 = dirnode_new(), *dirnode2;
    shadow_t * shdw1 = NULL;
    const shadow_t * shdw2 = NULL;
    ucafs_entry_type atype;
    const char *link_fname = "link.txt", *fname = "dummy_dirnode",
               *target_path = "./dell.txt";
    int len, link_info_len;
    link_info_t * link_info = NULL;
    const link_info_t * link_info1;

    len = strlen(target_path);
    link_info_len = len + sizeof(link_info_t) + 1;
    link_info = (link_info_t *)calloc(1, link_info_len);

    ASSERT_FALSE(link_info == NULL) << "allocation failed";

    link_info->total_len = link_info_len;
    link_info->type = UC_SOFTLINK;
    /* the meta file is useless */
    memcpy(&link_info->target_link, target_path, len);

    /* 5 - add it to the dirnode */
    shdw1 = dirnode_add_link(dirnode1, link_fname, link_info);
    ASSERT_FALSE(shdw1 == NULL) << "dirnode_add_link FAILED :(";

    shdw2 = dirnode_traverse(dirnode1, link_fname, UC_LINK, &atype, &link_info1);
    ASSERT_FALSE(shdw2 == NULL);

    ASSERT_TRUE(dirnode_write(dirnode1, fname));

    dirnode_free(dirnode1);
}
#endif
