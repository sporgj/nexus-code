#pragma once

#include "datalog.h"

dl_db_t
datalog_engine_create();

void
datalog_engine_destroy(dl_db_t db);

bool
datalog_engine_is_true(dl_db_t db,
                       char *  permission_str,
                       char *  user_uuid_str,
                       char *  obj_uuid_str);
