#include <stdio.h>
#include <sqlite3.h>
#include "../../include/database.h"

// Global database connection declaration
sqlite3 *g_db = NULL;