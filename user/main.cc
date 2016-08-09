/**
 *
 * UCAFS userland daemon process
 * @author judicael 
 *
 */
#include <glog/logging.h>

#include <common.h>

#include "uspace.h"

const char * gbl_temp_dnode_path = UCAFS_TEMP_DNODE_STR;

int main(int argc, char ** argv)
{
    google::InitGoogleLogging("--logtostderr=1");

    return 0;
}
