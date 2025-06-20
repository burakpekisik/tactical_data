/**
 * @file create.c
 * @brief Veritabanı oluşturma ve başlatma işlemleri
 * @details Bu dosya SQLite3 veritabanının başlatılması, tablo oluşturulması
 *          ve veritabanı bağlantısı yönetimi için gerekli fonksiyonları içerir.
 *          Tactical Data Transfer System için UNITS ve REPORTS tablolarını oluşturur.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 * @ingroup database
 */

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "../../include/database.h"
#include "logger.h"

/**
 * @brief Global veritabanı bağlantısı
 * @details Uygulama boyunca kullanılan SQLite3 veritabanı bağlantı pointer'ı.
 *          NULL değeri bağlantının kapalı olduğunu gösterir.
 * @note Thread-safe değil, tek thread kullanımı için tasarlanmış
 * @warning Global değişken, dikkatli kullanılmalı
 */
sqlite3 *g_db = NULL;

/**
 * @brief Veritabanını başlatır ve bağlantı açar
 * @details Belirtilen path'de SQLite3 veritabanını açar veya oluşturur.
 *          Dosya mevcut değilse otomatik olarak oluşturulur.
 * 
 * @param db_path Veritabanı dosya yolu (örn: "tactical_data.db")
 * @return int İşlem sonucu
 * @retval 0 Başarılı veritabanı açılışı
 * @retval -1 Veritabanı açma hatası
 * 
 * @note Global g_db pointer'ı bu fonksiyonla set edilir
 * @warning db_path NULL olmamalıdır
 * @warning Mevcut açık bağlantı varsa kapatılmaz
 * 
 * @see db_close(), db_create_tables()
 */
int db_init(const char *db_path) {
    int rc = sqlite3_open(db_path, &g_db);
    
    if(rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(g_db));
        return -1;
    } else {
        PRINTF_LOG("Database opened successfully: %s\n", db_path);
        return 0;
    }
}

/**
 * @brief Veritabanı tablolarını oluşturur
 * @details Tactical data transfer sistemi için gerekli UNITS ve REPORTS
 *          tablolarını oluşturur. Foreign key kısıtlamalarını etkinleştirir.
 * 
 * Oluşturulan Tablolar:
 * 
 * **UNITS Tablosu:**
 * - ID: Primary key (auto-increment)
 * - UNIT_ID: Benzersiz unit identifier (TEXT, UNIQUE)
 * - UNIT_NAME: Unit adı (TEXT, NOT NULL)
 * - UNIT_TYPE: Unit tipi (TEXT, NOT NULL)
 * - LOCATION: Konum bilgisi (TEXT, opsiyonel)
 * - ACTIVE: Aktiflik durumu (INTEGER, default 1)
 * - CREATED_AT: Oluşturulma zamanı (DATETIME, auto)
 * 
 * **REPORTS Tablosu:**
 * - ID: Primary key (auto-increment)
 * - UNIT_ID: Unit referansı (FOREIGN KEY -> UNITS.ID)
 * - STATUS: Rapor durumu (TEXT, NOT NULL)
 * - LATITUDE: Enlem koordinatı (REAL, NOT NULL)
 * - LONGITUDE: Boylam koordinatı (REAL, NOT NULL)
 * - DESCRIPTION: Açıklama (TEXT, opsiyonel)
 * - TIMESTAMP: Unix timestamp (INTEGER, NOT NULL)
 * - CREATED_AT: Oluşturulma zamanı (DATETIME, auto)
 * 
 * @return int İşlem sonucu
 * @retval 0 Başarılı tablo oluşturma
 * @retval -1 Tablo oluşturma hatası veya veritabanı başlatılmamış
 * 
 * @note IF NOT EXISTS kullanır, mevcut tablolar etkilenmez
 * @note Foreign key constraints CASCADE DELETE ile yapılandırılır
 * @warning db_init() fonksiyonu önceden çağrılmalıdır
 * 
 * @see db_init(), db_close()
 */
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
        PRINTF_LOG("UNITS table created successfully\n");
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
        PRINTF_LOG("REPORTS table created successfully\n");
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

/**
 * @brief Veritabanı bağlantısını güvenli şekilde kapatır
 * @details Açık olan SQLite3 veritabanı bağlantısını kapatır ve
 *          global pointer'ı NULL olarak resetler.
 * 
 * @return int İşlem sonucu
 * @retval 0 Başarılı bağlantı kapatma
 * @retval -1 Kapatılacak bağlantı yok (zaten kapalı)
 * 
 * @note Global g_db pointer'ı NULL olarak resetlenir
 * @note SQLite3 resources otomatik olarak temizlenir
 * @note Thread-safe değil, dikkatli kullanım gerekli
 * 
 * @see db_init()
 */
int db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
        PRINTF_LOG("Database closed successfully\n");
        return 0;
    }
    return -1;
}