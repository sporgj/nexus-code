#include <nexus_backend.h>


static int
init(void)
{

    printf("Initializing Cleartext backend\n");

    return 0;
}


static struct nexus_backend_impl clear_impl = {
    .name = "CLEARTEXT",
    .init = init
};


nexus_register_backend(clear_impl);
