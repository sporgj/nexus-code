/**
 * For testing different subcomponents of the NeXUS vfs
 *
 * @author judicael
 */

#include "nexus_tests.h"

void
test_path_builder()
{
    char *                path_str = NULL;
    size_t                i        = 0;
    size_t                count    = 3;
    struct path_builder * builder  = NULL;
    struct uuid           uuid;

    builder = path_alloc();
    
    for (; i < count; i++) {
        nexus_uuid(&uuid);
        path_push(builder, &uuid);

        path_str = path_string(builder, TEST_METADATA_PATH);
        printf("%s\n", path_str);
    }

    path_free(builder);
}

int main()
{
    compute_encoded_str_size();
    test_path_builder();
    return 0;
}
