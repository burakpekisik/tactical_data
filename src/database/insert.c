#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "../../include/database.h"

extern sqlite3 *g_db;

int db_insert_unit(const unit_t *unit) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "INSERT INTO UNITS (UNIT_ID, UNIT_NAME, UNIT_TYPE, LOCATION, ACTIVE) "
        "VALUES ('%s', '%s', '%s', '%s', %d);",
        unit->unit_id, unit->unit_name, unit->unit_type, 
        unit->location, unit->active);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error inserting unit: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        printf("Unit '%s' inserted successfully\n", unit->unit_id);
        return sqlite3_last_insert_rowid(g_db);
    }
}

int db_insert_report(const report_t *report) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "INSERT INTO REPORTS (UNIT_ID, STATUS, LATITUDE, LONGITUDE, DESCRIPTION, TIMESTAMP) "
        "VALUES (%d, '%s', %.6f, %.6f, '%s', %ld);",
        report->unit_id, report->status, report->latitude, report->longitude,
        report->description, report->timestamp);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error inserting report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        printf("Report for unit ID %d inserted successfully\n", report->unit_id);
        return sqlite3_last_insert_rowid(g_db);
    }
}