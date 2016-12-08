#include <cstdlib>
#include <ctime>

#include "uc_test.h"
#include "uc_utils.h"

#include <uc_fetchstore.h>
#include <uc_sgx.h>

#include <sys/param.h>

int xfer_size_test[] = {16, 512, 4096};
int file_size_test[] = {107, 32, 567, 34};

void fill_buffer(char * buffer, int len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = rand() % CHAR_MAX;
    }
}

TEST(UC_FETCHSTORE, SanityTest)
{
    int ret, bytes_left, len, total_len, xfer_id, new_fbox_len,
        file_size = file_size_test[0], xfer_buflen = xfer_size_test[0];
    char *temp, *input, *p_input, *output, *p_output;
    uint8_t **buf;
    sds path = MK_PATH("file.txt");
    srand(time(NULL));

    /* create our file */
    ASSERT_EQ(0, dirops_new(path, UC_FILE, &temp)) << "dirops_new failed";

    /* initalize the store */
    ASSERT_EQ(0, store_start(path, xfer_buflen, 0, file_size, 0, &xfer_id,
                             &new_fbox_len));

    /* start create variables */
    total_len = new_fbox_len + file_size;
    ASSERT_FALSE((input = (char *)malloc(file_size)) == NULL);
    ASSERT_FALSE((output = (char *)malloc(total_len)) == NULL);

    cout << "filelen = " << file_size << ", total_len = " << total_len << endl;

    fill_buffer(input, file_size);

    /* now store the data */
    p_input = input, p_output = output;
    bytes_left = file_size;
    while (bytes_left > 0) {
        len = MIN(xfer_buflen, bytes_left);

        ASSERT_FALSE((buf = store_get_buffer(xfer_id, len)) == NULL);

        // now copy the data
        memcpy(*buf, p_input, len);

        ASSERT_EQ(0, store_data(buf));

        memcpy(p_output, *buf, len);

        bytes_left -= len;
        p_input += len;
        p_output += len;
    }

    /* now lets retrieve our fbox data */
    bytes_left = new_fbox_len;
    cout << "Copying fbox. len = " << bytes_left << endl;
    while (bytes_left > 0) {
        len = MIN(xfer_buflen, bytes_left);

        ASSERT_EQ(0, store_fbox(UCAFS_FBOX_READ, buf));

        memcpy(p_output, *buf, len);

        bytes_left -= len;
        p_output += len;
    }

    ASSERT_EQ(0, store_finish(xfer_id));
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
