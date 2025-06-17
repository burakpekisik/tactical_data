#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "../../include/database.h"

// Global database connection
sqlite3 *g_db = NULL;

int db_init(const char *db_path) {
    int rc = sqlite3_open(db_path, &g_db);
    
    if(rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(g_db));
        return -1;
    } else {
        printf("Database opened successfully: %s\n", db_path);
        return 0;
    }
}

int db_create_tables(void) {
    char *zErrMsg = 0;
    int rc;
    char *sql;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    // Create UNITS table
    sql = "CREATE TABLE IF NOT EXISTS UNITS("
          "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
          "UNIT_ID TEXT NOT NULL UNIQUE,"
          "UNIT_NAME TEXT NOT NULL,"
          "UNIT_TYPE TEXT NOT NULL,"
          "LOCATION TEXT,"
          "ACTIVE INTEGER DEFAULT 1,"
          "CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP"
          ");";

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating UNITS table: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        printf("UNITS table created successfully\n");
    }

    // Create REPORTS table with foreign key
    sql = "CREATE TABLE IF NOT EXISTS REPORTS("
          "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
          "UNIT_ID INTEGER NOT NULL,"
          "STATUS TEXT NOT NULL,"
          "LATITUDE REAL NOT NULL,"
          "LONGITUDE REAL NOT NULL,"
          "DESCRIPTION TEXT,"
          "TIMESTAMP INTEGER NOT NULL,"
          "CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP,"
          "FOREIGN KEY (UNIT_ID) REFERENCES UNITS(ID) ON DELETE CASCADE"
          ");";

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating REPORTS table: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        printf("REPORTS table created successfully\n");
    }

    // Enable foreign key constraints
    sql = "PRAGMA foreign_keys = ON;";
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error enabling foreign keys: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }

    return 0;
}

int db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        printf("Database closed successfully\n");
        return 0;
    }
    return -1;
}