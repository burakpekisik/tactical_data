#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "../../include/database.h"

extern sqlite3 *g_db;

int db_update_unit(int id, const unit_t *unit) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE UNITS SET UNIT_ID='%s', UNIT_NAME='%s', UNIT_TYPE='%s', "
        "LOCATION='%s', ACTIVE=%d WHERE ID=%d;",
        unit->unit_id, unit->unit_name, unit->unit_type,
        unit->location, unit->active, id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating unit: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            printf("Unit ID %d updated successfully\n", id);
            return 0;
        } else {
            printf("No unit found with ID %d\n", id);
            return -1;
        }
    }
}

int db_update_report(int id, const report_t *report) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE REPORTS SET UNIT_ID=%d, STATUS='%s', LATITUDE=%.6f, "
        "LONGITUDE=%.6f, DESCRIPTION='%s', TIMESTAMP=%ld WHERE ID=%d;",
        report->unit_id, report->status, report->latitude, report->longitude,
        report->description, report->timestamp, id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            printf("Report ID %d updated successfully\n", id);
            return 0;
        } else {
            printf("No report found with ID %d\n", id);
            return -1;
        }
    }
}

int db_get_unit_by_id(int id, unit_t *unit) {
    sqlite3_stmt *stmt;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), "SELECT * FROM UNITS WHERE ID = %d", id);
    
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        memset(unit, 0, sizeof(unit_t));
        unit->id = sqlite3_column_int(stmt, 0);
        strncpy(unit->unit_id, (char*)sqlite3_column_text(stmt, 1), sizeof(unit->unit_id) - 1);
        strncpy(unit->unit_name, (char*)sqlite3_column_text(stmt, 2), sizeof(unit->unit_name) - 1);
        strncpy(unit->unit_type, (char*)sqlite3_column_text(stmt, 3), sizeof(unit->unit_type) - 1);
        if (sqlite3_column_text(stmt, 4)) {
            strncpy(unit->location, (char*)sqlite3_column_text(stmt, 4), sizeof(unit->location) - 1);
        }
        unit->active = sqlite3_column_int(stmt, 5);
        if (sqlite3_column_text(stmt, 6)) {
            strncpy(unit->created_at, (char*)sqlite3_column_text(stmt, 6), sizeof(unit->created_at) - 1);
        }
        
        sqlite3_finalize(stmt);
        return 0;
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }
}

int db_get_report_by_id(int id, report_t *report) {
    sqlite3_stmt *stmt;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), "SELECT * FROM REPORTS WHERE ID = %d", id);
    
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        memset(report, 0, sizeof(report_t));
        report->id = sqlite3_column_int(stmt, 0);
        report->unit_id = sqlite3_column_int(stmt, 1);
        strncpy(report->status, (char*)sqlite3_column_text(stmt, 2), sizeof(report->status) - 1);
        report->latitude = sqlite3_column_double(stmt, 3);
        report->longitude = sqlite3_column_double(stmt, 4);
        if (sqlite3_column_text(stmt, 5)) {
            strncpy(report->description, (char*)sqlite3_column_text(stmt, 5), sizeof(report->description) - 1);
        }
        report->timestamp = sqlite3_column_int64(stmt, 6);
        if (sqlite3_column_text(stmt, 7)) {
            strncpy(report->created_at, (char*)sqlite3_column_text(stmt, 7), sizeof(report->created_at) - 1);
        }
        
        sqlite3_finalize(stmt);
        return 0;
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }
}