#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

// Database connection structure
typedef struct {
    sqlite3 *db;
    char *db_path;
} db_connection_t;

// Unit structure
typedef struct {
    int id;
    char unit_id[50];
    char unit_name[100];
    char unit_type[50];
    char location[100];
    int active;
    char created_at[32];
} unit_t;

// Report structure
typedef struct {
    int id;
    int unit_id;
    char status[50];
    double latitude;
    double longitude;
    char description[500];
    long timestamp;
    char created_at[32];
} report_t;

// Database functions
int db_init(const char *db_path);
int db_create_tables(void);
int db_close(void);

// Unit operations
int db_insert_unit(const unit_t *unit);
int db_select_units(unit_t **units, int *count);
int db_update_unit(int id, const unit_t *unit);
int db_delete_unit(int id);
int db_get_unit_by_id(int id, unit_t *unit);

// Report operations
int db_insert_report(const report_t *report);
int db_select_reports(report_t **reports, int *count);
int db_select_reports_by_unit(int unit_id, report_t **reports, int *count);
int db_update_report(int id, const report_t *report);
int db_delete_report(int id);
int db_get_report_by_id(int id, report_t *report);

// Utility functions
void db_free_units(unit_t *units, int count);
void db_free_reports(report_t *reports, int count);

// Test functions
int db_insert_test_data(void);

#endif // DATABASE_H
