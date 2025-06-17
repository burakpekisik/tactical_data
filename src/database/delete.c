#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "../../include/database.h"

extern sqlite3 *g_db;

int db_delete_unit(int id) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    // First delete associated reports (due to foreign key constraint)
    snprintf(sql, sizeof(sql), "DELETE FROM REPORTS WHERE UNIT_ID = %d;", id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting unit reports: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }

    // Then delete the unit
    snprintf(sql, sizeof(sql), "DELETE FROM UNITS WHERE ID = %d;", id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting unit: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            printf("Unit ID %d and associated reports deleted successfully\n", id);
            return 0;
        } else {
            printf("No unit found with ID %d\n", id);
            return -1;
        }
    }
}

int db_delete_report(int id) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), "DELETE FROM REPORTS WHERE ID = %d;", id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            printf("Report ID %d deleted successfully\n", id);
            return 0;
        } else {
            printf("No report found with ID %d\n", id);
            return -1;
        }
    }
}

void db_free_units(unit_t *units, int count __attribute__((unused))) {
    if (units) {
        free(units);
    }
}

void db_free_reports(report_t *reports, int count __attribute__((unused))) {
    if (reports) {
        free(reports);
    }
}

// // Test function
// int main(int argc, char* argv[]) {
//     if (db_init("tactical_data.db") != 0) {
//         return 1;
//     }

//     printf("Testing delete operations...\n");
    
//     // List current units and reports before deletion
//     unit_t *units;
//     int unit_count;
    
//     if (db_select_units(&units, &unit_count) == 0) {
//         printf("Units before deletion: %d\n", unit_count);
//         for (int i = 0; i < unit_count; i++) {
//             printf("  Unit ID %d: %s (%s)\n", 
//                    units[i].id, units[i].unit_id, units[i].unit_name);
//         }
//         free(units);
//     }

//     report_t *reports;
//     int report_count;
    
//     if (db_select_reports(&reports, &report_count) == 0) {
//         printf("Reports before deletion: %d\n", report_count);
//         for (int i = 0; i < report_count; i++) {
//             printf("  Report ID %d: Unit %d - %s\n", 
//                    reports[i].id, reports[i].unit_id, reports[i].status);
//         }
//         free(reports);
//     }

//     // Test deleting a specific report
//     printf("\nDeleting report ID 2...\n");
//     db_delete_report(2);

//     // Test deleting a unit (this will also delete associated reports)
//     printf("\nDeleting unit ID 1 (and its reports)...\n");
//     db_delete_unit(1);

//     // Show remaining data
//     if (db_select_units(&units, &unit_count) == 0) {
//         printf("\nRemaining units: %d\n", unit_count);
//         for (int i = 0; i < unit_count; i++) {
//             printf("  Unit ID %d: %s (%s)\n", 
//                    units[i].id, units[i].unit_id, units[i].unit_name);
//         }
//         free(units);
//     }

//     if (db_select_reports(&reports, &report_count) == 0) {
//         printf("Remaining reports: %d\n", report_count);
//         for (int i = 0; i < report_count; i++) {
//             printf("  Report ID %d: Unit %d - %s\n", 
//                    reports[i].id, reports[i].unit_id, reports[i].status);
//         }
//         free(reports);
//     }

//     db_close();
//     return 0;
// }
