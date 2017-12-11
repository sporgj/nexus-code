#pragma once

#include <stdint.h>


int dispatch_nexus_command(uint8_t   * cmd_buf,
			   uint32_t    cmd_size,
			   uint8_t  ** resp_buf,
			   uint32_t  * resp_size);
