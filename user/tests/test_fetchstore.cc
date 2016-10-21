#include <cstdlib>
#include <ctime>

#include "uc_test.h"
#include "uc_utils.h"

#include <uc_fileops.h>
#include <uc_sgx.h>

#define FILE_LEN 10
#define CHUNK_LEN 16 + 1

static uint8_t *input_buffer, *output_buffer, *temp_buffer;

static void
generate_stream()
{
    uinfo("Generating stream...");

    input_buffer = (uint8_t *)malloc(FILE_LEN);
    ASSERT_TRUE(input_buffer != NULL) << "Malloc failed";

    temp_buffer = (uint8_t *)malloc(FILE_LEN);
    ASSERT_TRUE(temp_buffer != NULL) << "Malloc failed";

    output_buffer = (uint8_t *)malloc(FILE_LEN);
    ASSERT_TRUE(output_buffer != NULL) << "Malloc failed";

    /* generate the random stream */
    srand(time(0));
    for (size_t i = 0; i < FILE_LEN; i++) {
        input_buffer[i] = rand() % UINT8_MAX;
    }
}

static void
run_fetch_store(int op, sds path, uint8_t * p_input, uint8_t * p_output)
{
    int ret, xfer_id;
    uint8_t ** buf;
    size_t len;

    /* start encryption */
    ASSERT_EQ(0, fileops_start(op, path, CHUNK_LEN, FILE_LEN, &xfer_id))
        << "fileops_start failed";

    uinfo("%s...", op == UC_ENCRYPT ? "Uploading" : "Downloading");
    for (size_t i = 0; i < FILE_LEN; i += CHUNK_LEN) {
        len = (FILE_LEN - i < CHUNK_LEN) ? (FILE_LEN - i) : CHUNK_LEN;

        buf = fileops_get_buffer(xfer_id, len);
        ASSERT_TRUE(buf != NULL) << "fileops_get_context failed";

        /* this portion is done by rpc.c */
        memcpy(*buf, p_input + i, len);
        ASSERT_EQ(0, fileops_process_data(buf));
        memcpy(p_output + i, *buf, len);
    }
    ASSERT_EQ(0, fileops_finish(xfer_id));
}

TEST(UC_FETCHSTORE, LocalTest)
{
    int ret;
    char * test;
    size_t xfer_id, len;
    const char * fname = "test.txt";
    sds path = MK_PATH(fname);

    /* creating the default file */
    ASSERT_EQ(0, dirops_new(path, UCAFS_TYPE_FILE, &test))
        << "dirops_new failed";

    generate_stream();
    run_fetch_store(UC_ENCRYPT, path, input_buffer, output_buffer);
    run_fetch_store(UC_DECRYPT, path, output_buffer, temp_buffer);

    printf("\n");
    uinfo("Input..");
    hexdump(input_buffer, 32);

    printf("\n");
    uinfo("Output..");
    hexdump(output_buffer, 32);

    printf("\n");
    uinfo("Ttemp...");
    hexdump(temp_buffer, 32);

    printf("\n");

    ASSERT_EQ(0, memcmp(input_buffer, temp_buffer, FILE_LEN))
        << "Encryption did not work";

    sdsfree(path);
}

int
main(int argc, char ** argv)
{
    init_systems();
    create_default_dnode();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
