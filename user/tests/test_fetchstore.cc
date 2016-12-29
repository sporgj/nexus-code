#include <cstdlib>
#include <ctime>

#include "uc_test.h"
#include "uc_utils.h"

#include <uc_fetchstore.h>
#include <uc_sgx.h>

#include <sys/param.h>

int xfer_size_test[] = { 16, 512, 4096 };
int file_size_test[] = { 107, 32, 567, 34 };

void
fill_buffer(uint8_t * buffer, int len)
{
    for (size_t i = 0; i < len; i++) {
        buffer[i] = 0; //rand() % CHAR_MAX;
    }
}

void
perform_crypto(uc_xfer_op_t op,
               char * path,
               int xfer_buflen,
               int offset,
               int file_size,
               uint8_t * p_input,
               uint8_t * p_output)
{
    xfer_req_t _req, *req = &_req;
    xfer_rsp_t _rsp, *rsp = &_rsp;
    int bytes_left, len;

    _req = (xfer_req_t){.op = op,
                        .xfer_size = xfer_buflen,
                        .offset = offset,
                        .file_size = file_size };

    ASSERT_EQ(0, fetchstore_init(req, path, rsp));

    bytes_left = file_size;
    while (bytes_left) {
        len = MIN(bytes_left, rsp->buflen);

        memcpy(rsp->uaddr, p_input, len);

        ASSERT_EQ(0, fetchstore_run(rsp->xfer_id, len));

        memcpy(p_output, rsp->uaddr, len);

        bytes_left -= len;
        p_input += len;
        p_output += len;
    }

    ASSERT_EQ(0, fetchstore_finish(rsp->xfer_id));
}

TEST(FETCHSTORE, Test1)
{
    int file_size = 2 * UCAFS_CHUNK_SIZE;
    const char * fname = "file.txt";
    sds path = MK_PATH(fname);
    char * test;
    uint8_t **buf, *temp, *input, *output;

    srand(time(NULL));

    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test)) << "dirops_new failed";
    uinfo("File: %s", test);

    /* start create variables */
    ASSERT_FALSE((input = (uint8_t *)malloc(file_size)) == NULL);
    ASSERT_FALSE((output = (uint8_t *)malloc(file_size)) == NULL);
    ASSERT_FALSE((temp = (uint8_t *)malloc(file_size)) == NULL);

    fill_buffer(input, file_size);

    perform_crypto(UCAFS_STORE, path, UCAFS_CHUNK_SIZE, 0, file_size, input, output);
    perform_crypto(UCAFS_FETCH, path, UCAFS_CHUNK_SIZE, 0, file_size, output, temp);

    uinfo("input");
    hexdump(input, MIN(32, file_size));

    uinfo("output");
    hexdump(output, MIN(32, file_size));

    uinfo("temp");
    hexdump(temp, MIN(32, file_size));
}

int
main(int argc, char ** argv)
{
    setup_repo_path();
    create_default_dnode();
    init_systems();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
