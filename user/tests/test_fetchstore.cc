#include <cstdlib>
#include <ctime>

#include "uc_test.h"
#include "uc_utils.h"

#include <uc_fileops.h>
#include <uc_sgx.h>

#include <sys/param.h>

#define FILE_LEN 1024
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
run_fetch_store(int op,
                sds path,
                uint8_t * p_input,
                uint8_t * p_output,
                int blen,
                int offset)
{
    int ret, xfer_id;
    uint8_t ** buf;
    size_t len, bytes_left = blen;

    /* start encryption */
    ASSERT_EQ(0, fileops_start(op, path, CHUNK_LEN, offset, blen, &xfer_id))
        << "fileops_start failed";

    uinfo("%s...", op == UC_ENCRYPT ? "Uploading" : "Downloading");
    for (size_t i = 0; i < blen; i += CHUNK_LEN) {
        len = MIN(bytes_left, CHUNK_LEN);

        buf = fileops_get_buffer(xfer_id, len);
        ASSERT_TRUE(buf != NULL) << "fileops_get_context failed";

        /* this portion is done by rpc.c */
        memcpy(*buf, p_input + offset + i, len);
        ASSERT_EQ(0, fileops_process_data(buf));
        memcpy(p_output + offset + i, *buf, len);

        bytes_left -= len;
    }
    ASSERT_EQ(0, fileops_finish(xfer_id));
}

TEST(UC_FETCHSTORE, LocalTest)
{
    int ret;
    char * test;
    const char * fname = "test.txt";
    sds path = MK_PATH(fname);

    /* creating the default file */
    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test))
        << "dirops_new failed";

    generate_stream();
    run_fetch_store(UC_ENCRYPT, path, input_buffer, output_buffer, FILE_LEN, 0);
    run_fetch_store(UC_DECRYPT, path, output_buffer, temp_buffer, FILE_LEN, 0);

    printf("\n");
    uinfo("Input..");
    hexdump(input_buffer, MIN(FILE_LEN, 32));

    printf("\n");
    uinfo("Output..");
    hexdump(output_buffer, MIN(FILE_LEN, 32));

    printf("\n");
    uinfo("Ttemp...");
    hexdump(temp_buffer, MIN(FILE_LEN, 32));

    printf("\n");

    ASSERT_EQ(0, memcmp(input_buffer, temp_buffer, FILE_LEN))
        << "Encryption did not work";

    ASSERT_EQ(0, dirops_remove(path, UC_FILE, &test))
        << "dirops_remove failed";

    free(input_buffer);
    free(output_buffer);
    free(temp_buffer);

    sdsfree(path);
}

TEST(UC_FETCHSTORE, OffsetTest)
{
    int ret, offset;
    char * test;
    const char * fname = "test.txt";
    sds path = MK_PATH(fname);

    srand(time(NULL));
    offset = ((rand() % FILE_LEN) / 16) * 16;

    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test))
        << "dirops_new failed";

    cout << "Running with offset = " << offset << endl;
    generate_stream();

    printf("\n");
    uinfo("Input..");
    hexdump(input_buffer, MIN(FILE_LEN, 32));
    run_fetch_store(UC_ENCRYPT, path, input_buffer, output_buffer, FILE_LEN, 0);

    printf("\n");
    uinfo("Output..");
    hexdump(output_buffer, MIN(FILE_LEN, 32));

    run_fetch_store(UC_DECRYPT, path, output_buffer, temp_buffer,
                    FILE_LEN - offset, offset);

    printf("\n");
    uinfo("Temp...");
    hexdump(temp_buffer, MIN(FILE_LEN, 32));

    ASSERT_EQ(0, memcmp(input_buffer + offset, temp_buffer + offset,
                        FILE_LEN - offset))
        << "Encryption did not work";

    ASSERT_EQ(0, dirops_remove(path, UC_FILE, &test))
        << "dirops_remove failed";

    free(input_buffer);
    free(output_buffer);
    free(temp_buffer);

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
