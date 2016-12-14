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
        buffer[i] = rand() % CHAR_MAX;
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
    int xfer_id, new_fbox_len, bytes_left, len, chunk_len, nbytes;
    uint8_t **buf;

    chunk_len = bytes_left = file_size;

next_chunk:
    if (op == UCAFS_STORE) {
        bytes_left = MIN(chunk_len, UCAFS_CHUNK_SIZE);
    }

    /* initalize the store */
    ASSERT_EQ(0, fetchstore_start(op, path, xfer_buflen, offset, file_size,
                                  0, &xfer_id, &new_fbox_len));

    printf("%s: len=%d, buflen=%d, bytes_left=%d, offset=%d\n",
           (op == UCAFS_STORE ? "store" : "fetch"), file_size, xfer_buflen,
           chunk_len, offset);

    nbytes = 0;
    /* now store the data */
    while (bytes_left > 0) {
        len = MIN(xfer_buflen, bytes_left);

        ASSERT_FALSE((buf = fetchstore_get_buffer(xfer_id, len)) == NULL);

        // now copy the data
        memcpy(*buf, p_input, len);

        ASSERT_EQ(0, fetchstore_data(buf));

        memcpy(p_output, *buf, len);

        nbytes += len;
        bytes_left -= len;
        p_input += len;
        p_output += len;
    }

    ASSERT_EQ(0, fetchstore_finish(xfer_id));

    if (op == UCAFS_STORE) {
        offset += nbytes;
        chunk_len -= nbytes;
        if (chunk_len > 0) {
            goto next_chunk;
        }
    }
}

TEST(UC_FETCHSTORE, SanityTest)
{
    int file_size = file_size_test[0], xfer_buflen = xfer_size_test[0];
    uint8_t **buf, *temp, *input, *output;
    char * test;
    sds path = MK_PATH("file.txt");
    srand(time(NULL));

    /* create our file */
    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test)) << "dirops_new failed";

    /* start create variables */
    ASSERT_FALSE((input = (uint8_t *)malloc(file_size)) == NULL);
    ASSERT_FALSE((output = (uint8_t *)malloc(file_size)) == NULL);
    ASSERT_FALSE((temp = (uint8_t *)malloc(file_size)) == NULL);

    fill_buffer(input, file_size);

    perform_crypto(UCAFS_STORE, path, xfer_buflen, 0, file_size, input, output);
    perform_crypto(UCAFS_FETCH, path, xfer_buflen, 0, file_size, output, temp);

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
