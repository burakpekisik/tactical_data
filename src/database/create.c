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
#include "database.h"
#include "logger.h"
#include "config.h"

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

// Tekrarlayan SQL çalıştırma ve loglama işlemi için yardımcı fonksiyon
int exec_sql_with_log(const char* sql, const char* success_log, const char* error_log) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "%s: %s\n", error_log, zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else if (success_log) {
        PRINTF_LOG("%s\n", success_log);
    }
    return 0;
}

/**
 * @brief Veritabanı tablolarını oluşturur
 * @details Tactical data transfer sistemi için gerekli UNITS, USERS ve REPORTS
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
 * **USERS Tablosu:**
 * - ID: Primary key (auto-increment)
 * - UNIT_ID: Unit referansı (FOREIGN KEY -> UNITS.ID)
 * - USERNAME: Kullanıcı adı (TEXT, NOT NULL, UNIQUE)
 * - NAME: Adı (TEXT, NOT NULL)
 * - SURNAME: Soyadı (TEXT, NOT NULL)
 * - PASSWORD: Şifre (TEXT, NOT NULL)
 * - SALT: Tuz (şifreleme için) (TEXT, NOT NULL)
 * - PRIVILEGE: Kullanıcı yetkisi (INTEGER, NOT NULL)
 * - CREATED_AT: Oluşturulma zamanı (DATETIME, auto)
 * 
 * **REPORTS Tablosu:**
 * - ID: Primary key (auto-increment)
 * - USER_ID: Kullanıcı referansı (FOREIGN KEY -> USERS.ID)
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
    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    if (exec_sql_with_log(
        "CREATE TABLE IF NOT EXISTS UNITS("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "UNIT_ID TEXT NOT NULL UNIQUE,"
        "UNIT_NAME TEXT NOT NULL,"
        "UNIT_TYPE TEXT NOT NULL,"
        "LOCATION TEXT,"
        "ACTIVE INTEGER DEFAULT 1,"
        "CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");",
        "UNITS table created successfully",
        "SQL error creating UNITS table") != 0) return -1;

    if (exec_sql_with_log(
        "CREATE TABLE IF NOT EXISTS USERS(" 
        "ID INTEGER PRIMARY KEY AUTOINCREMENT," 
        "UNIT_ID INTEGER," 
        "USERNAME TEXT NOT NULL UNIQUE," 
        "NAME TEXT NOT NULL," 
        "SURNAME TEXT NOT NULL," 
        "PASSWORD TEXT NOT NULL," 
        "SALT TEXT NOT NULL," 
        "PRIVILEGE INTEGER NOT NULL," 
        "CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP," 
        "FOREIGN KEY (UNIT_ID) REFERENCES UNITS(ID) ON DELETE SET NULL" 
        ");",
        "USERS table created successfully",
        "SQL error creating USERS table") != 0) return -1;

    if (exec_sql_with_log(
        "CREATE TABLE IF NOT EXISTS REPORTS(" 
        "ID INTEGER PRIMARY KEY AUTOINCREMENT," 
        "USER_ID INTEGER NOT NULL," 
        "STATUS TEXT NOT NULL," 
        "LATITUDE REAL NOT NULL," 
        "LONGITUDE REAL NOT NULL," 
        "DESCRIPTION TEXT," 
        "TIMESTAMP INTEGER NOT NULL," 
        "CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP," 
        "FOREIGN KEY (USER_ID) REFERENCES USERS(ID) ON DELETE CASCADE" 
        ");",
        "REPORTS table created successfully",
        "SQL error creating REPORTS table") != 0) return -1;

    if (exec_sql_with_log(
        "CREATE TABLE IF NOT EXISTS chat_rooms ("
        "room_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_name TEXT NOT NULL,"
        "creator_id TEXT NOT NULL,"
        "room_type INTEGER NOT NULL,"
        "max_users INTEGER NOT NULL DEFAULT 10,"
        "current_users INTEGER NOT NULL DEFAULT 0,"
        "allowed_user_ids TEXT,"
        "room_key BLOB NOT NULL,"
        "created_at INTEGER NOT NULL,"
        "is_active INTEGER NOT NULL DEFAULT 1"
        ");",
        "ROOMS table created successfully",
        "SQL error creating ROOMS table") != 0) return -1;

    if (exec_sql_with_log(
        "CREATE TABLE IF NOT EXISTS chat_messages ("
        "message_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_id INTEGER NOT NULL,"
        "sender_id TEXT NOT NULL,"
        "sender_name TEXT NOT NULL,"
        "message TEXT NOT NULL," // Şifreli mesaj
        "timestamp INTEGER NOT NULL,"
        "FOREIGN KEY (room_id) REFERENCES chat_rooms(room_id) ON DELETE CASCADE"
        ");",
        "MESSAGES table created successfully",
        "SQL error creating MESSAGES table") != 0) return -1;

    if (exec_sql_with_log(
        "PRAGMA foreign_keys = ON;",
        NULL,
        "SQL error enabling foreign keys") != 0) return -1;

    if (exec_sql_with_log(
        "CREATE INDEX IF NOT EXISTS idx_chat_rooms_creator ON chat_rooms(creator_id);",
        "ROOM INDEX for chat_rooms table created successfully",
        "SQL error creating ROOM INDEX for chat_rooms") != 0) return -1;

    if (exec_sql_with_log(
        "CREATE INDEX IF NOT EXISTS idx_chat_messages_room ON chat_messages(room_id, timestamp);",
        "MESSAGE INDEX for chat_messages table created successfully",
        "SQL error creating MESSAGE INDEX for chat_messages") != 0) return -1;

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