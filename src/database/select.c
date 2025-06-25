/**
 * @file select.c
 * @brief Veritabanı sorgulama ve veri çekme işlemleri
 * @details Bu dosya SQLite3 veritabanından unit ve report verilerinin sorgulanması,
 *          filtrelenmesi ve callback fonksiyonları ile veri toplanması işlemlerini
 *          içerir. Tactical Data Transfer System'in veri okuma katmanını oluşturur.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 * @ingroup database
 */

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "../../include/database.h"
#include "logger.h"
#include "jwt_manager.h"
#include "argon2.h"

/**
 * @brief External global veritabanı bağlantısı
 * @details create.c'de tanımlanan global veritabanı bağlantısına referans
 * @see g_db in create.c
 */
extern sqlite3 *g_db;

/**
 * @brief UNITS tablosu callback fonksiyonu
 * @details sqlite3_exec() tarafından çağrılan callback. Her unit record'u için
 *          çağrılır ve dynamic array'e unit verilerini ekler.
 * 
 * Callback Data Formatı:
 * - data[0]: unit_t** (units array pointer)
 * - data[1]: int* (current count)
 * - data[2]: int* (array capacity)
 * 
 * @param data Callback veri paketi (unit array, count, capacity)
 * @param argc Column sayısı
 * @param argv Column değerleri array'i
 * @param azColName Column isimleri array'i
 * @return int Callback sonucu (0: devam, non-zero: abort)
 * 
 * @note Dynamic memory reallocation yapabilir
 * @note NULL değerler güvenli şekilde handle edilir
 * @warning Buffer overflow koruması için strncpy kullanılır
 * 
 * @see db_select_all_units(), unit_t
 */
static int unit_callback(void *data, int argc, char **argv, char **azColName) {
    unit_t **units = (unit_t **)((void**)data)[0];
    int *count = (int *)((void**)data)[1];
    int *capacity = (int *)((void**)data)[2];

    if (*count >= *capacity) {
        *capacity *= 2;
        *units = realloc(*units, *capacity * sizeof(unit_t));
    }

    unit_t *unit = &(*units)[*count];
    memset(unit, 0, sizeof(unit_t));

    for(int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "ID") == 0 && argv[i]) {
            unit->id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "UNIT_ID") == 0 && argv[i]) {
            strncpy(unit->unit_id, argv[i], sizeof(unit->unit_id) - 1);
        } else if (strcmp(azColName[i], "UNIT_NAME") == 0 && argv[i]) {
            strncpy(unit->unit_name, argv[i], sizeof(unit->unit_name) - 1);
        } else if (strcmp(azColName[i], "UNIT_TYPE") == 0 && argv[i]) {
            strncpy(unit->unit_type, argv[i], sizeof(unit->unit_type) - 1);
        } else if (strcmp(azColName[i], "LOCATION") == 0 && argv[i]) {
            strncpy(unit->location, argv[i], sizeof(unit->location) - 1);
        } else if (strcmp(azColName[i], "ACTIVE") == 0 && argv[i]) {
            unit->active = atoi(argv[i]);
        } else if (strcmp(azColName[i], "CREATED_AT") == 0 && argv[i]) {
            strncpy(unit->created_at, argv[i], sizeof(unit->created_at) - 1);
        }
    }
    (*count)++;
    return 0;
}

/**
 * @brief REPORTS tablosu callback fonksiyonu
 * @details sqlite3_exec() tarafından çağrılan callback. Her report record'u için
 *          çağrılır ve dynamic array'e report verilerini ekler.
 * 
 * Callback Data Formatı:
 * - data[0]: report_t** (reports array pointer)
 * - data[1]: int* (current count)
 * - data[2: int* (array capacity)
 * 
 * @param data Callback veri paketi (report array, count, capacity)
 * @param argc Column sayısı
 * @param argv Column değerleri array'i
 * @param azColName Column isimleri array'i
 * @return int Callback sonucu (0: devam, non-zero: abort)
 * 
 * @note Koordinatlar atof() ile double'a çevrilir
 * @note Timestamp atol() ile long'a çevrilir
 * @note Dynamic memory reallocation yapabilir
 * @warning Buffer overflow koruması için strncpy kullanılır
 * 
 * @see db_select_all_reports(), report_t
 */
static int report_callback(void *data, int argc, char **argv, char **azColName) {
    report_t **reports = (report_t **)((void**)data)[0];
    int *count = (int *)((void**)data)[1];
    int *capacity = (int *)((void**)data)[2];

    if (*count >= *capacity) {
        *capacity *= 2;
        *reports = realloc(*reports, *capacity * sizeof(report_t));
    }

    report_t *report = &(*reports)[*count];
    memset(report, 0, sizeof(report_t));

    for(int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "ID") == 0 && argv[i]) {
            report->id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "USER_ID") == 0 && argv[i]) {
            report->user_id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "STATUS") == 0 && argv[i]) {
            strncpy(report->status, argv[i], sizeof(report->status) - 1);
        } else if (strcmp(azColName[i], "LATITUDE") == 0 && argv[i]) {
            report->latitude = atof(argv[i]);
        } else if (strcmp(azColName[i], "LONGITUDE") == 0 && argv[i]) {
            report->longitude = atof(argv[i]);
        } else if (strcmp(azColName[i], "DESCRIPTION") == 0 && argv[i]) {
            strncpy(report->description, argv[i], sizeof(report->description) - 1);
        } else if (strcmp(azColName[i], "TIMESTAMP") == 0 && argv[i]) {
            report->timestamp = atol(argv[i]);
        } else if (strcmp(azColName[i], "CREATED_AT") == 0 && argv[i]) {
            strncpy(report->created_at, argv[i], sizeof(report->created_at) - 1);
        }
    }
    (*count)++;
    return 0;
}

/**
 * @brief Tüm unit kayıtlarını sorgular
 * @details UNITS tablosundaki tüm kayıtları CREATED_AT'e göre ters sıralı (en yeni önce)
 *          olarak getirir. Dynamic array allocation kullanır.
 * 
 * Sorgu Özellikleri:
 * - ORDER BY CREATED_AT DESC (en yeni kayıtlar önce)
 * - Dynamic memory allocation (başlangıç 10, gerektiğinde 2x artış)
 * - Callback-based result processing
 * 
 * @param units [OUT] Unit array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen unit sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama
 * @retval -1 Sorgu hatası (database not initialized, SQL error)
 * 
 * @note units array'i çağıran tarafından free() edilmelidir
 * @note count 0 ise units NULL olabilir
 * @warning units ve count pointer'ları NULL olmamalıdır
 * 
 * @see unit_callback(), unit_t, db_select_reports()
 */
int db_select_units(unit_t **units, int *count) {
    char *zErrMsg = 0;
    int rc;
    char *sql = "SELECT * FROM UNITS ORDER BY CREATED_AT DESC";

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    *count = 0;
    int capacity = 10;
    *units = malloc(capacity * sizeof(unit_t));

    void *callback_data[] = {units, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, unit_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting units: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*units);
        return -1;
    }

    return 0;
}

/**
 * @brief Tüm report kayıtlarını sorgular
 * @details REPORTS tablosundaki tüm kayıtları TIMESTAMP'e göre ters sıralı (en yeni önce)
 *          olarak getirir. Dynamic array allocation kullanır.
 * 
 * Sorgu Özellikleri:
 * - ORDER BY TIMESTAMP DESC (en yeni raporlar önce)
 * - Dynamic memory allocation (başlangıç 10, gerektiğinde 2x artış)
 * - Callback-based result processing
 * - Tüm report alanları dahil (koordinatlar, durum, açıklama)
 * 
 * @param reports [OUT] Report array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen report sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama
 * @retval -1 Sorgu hatası (database not initialized, SQL error)
 * 
 * @note reports array'i çağıran tarafından free() edilmelidir
 * @note Koordinatlar double precision ile döner
 * @warning reports ve count pointer'ları NULL olmamalıdır
 * 
 * @see report_callback(), report_t, db_select_reports_by_unit()
 */
int db_select_reports(report_t **reports, int *count) {
    char *zErrMsg = 0;
    int rc;
    char *sql = "SELECT * FROM REPORTS ORDER BY ID ASC";

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    *count = 0;
    int capacity = 10;
    *reports = malloc(capacity * sizeof(report_t));

    void *callback_data[] = {reports, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, report_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting reports: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*reports);
        return -1;
    }

    return 0;
}

/**
 * @brief Belirli bir unit'e ait report kayıtlarını sorgular
 * @details Verilen unit_id'ye sahip tüm raporları TIMESTAMP'e göre ters sıralı
 *          (en yeni önce) olarak getirir. Unit-specific filtering yapar.
 * 
 * Sorgu Özellikleri:
 * - WHERE UNIT_ID = {unit_id} filter
 * - ORDER BY TIMESTAMP DESC (en yeni raporlar önce)
 * - Dynamic memory allocation
 * - Foreign key relationship ile UNITS tablosuna bağlı
 * 
 * @param unit_id Filtrelenecek unit'in database ID'si
 * @param reports [OUT] Report array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen report sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama (0 sonuç da başarılıdır)
 * @retval -1 Sorgu hatası (database not initialized, SQL error)
 * 
 * @note reports array'i çağıran tarafından free() edilmelidir
 * @note unit_id foreign key constraint ile validate edilir
 * @note count 0 ise unit'e ait report yok demektir
 * @warning reports ve count pointer'ları NULL olmamalıdır
 * @warning unit_id geçerli bir UNITS.ID olmalıdır
 * 
 * @see report_callback(), report_t, db_select_reports()
 */
int db_select_reports_by_user(int user_id, report_t **reports, int *count) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), 
        "SELECT * FROM REPORTS WHERE USER_ID = %d ORDER BY TIMESTAMP DESC", user_id);

    *count = 0;
    int capacity = 10;
    *reports = malloc(capacity * sizeof(report_t));

    void *callback_data[] = {reports, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, report_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting reports by user: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*reports);
        return -1;
    }

    return 0;
}

/**
 * @brief USERS tablosundan kullanıcıyı ID ile seçer
 * @details Verilen ID'ye sahip kullanıcıyı USERS tablosundan çeker.
 *
 * @param id Kullanıcı ID'si
 * @param unit_id [OUT] Bağlı olduğu unit'in ID'si
 * @param username [OUT] Kullanıcı adı
 * @param name [OUT] Adı
 * @param surname [OUT] Soyadı
 * @param password [OUT] Hashlenmiş şifre
 * @param salt [OUT] Kullanıcıya ait salt
 * @param privilege [OUT] Yetki seviyesi
 * @param created_at [OUT] Oluşturulma zamanı
 * @return int 0: Başarılı, -1: Hata veya kullanıcı yok
 */
int db_select_user_by_id(int id, int *unit_id, char *username, char *name, char *surname, char *password, char *salt, int *privilege, char *created_at) {
    char sql[256];
    sqlite3_stmt *stmt;
    int rc;
    snprintf(sql, sizeof(sql), "SELECT UNIT_ID, USERNAME, NAME, SURNAME, PASSWORD, SALT, PRIVILEGE, CREATED_AT FROM USERS WHERE ID = ?;");
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error preparing select user: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (unit_id) *unit_id = sqlite3_column_int(stmt, 0);
        if (username) strcpy(username, (const char*)sqlite3_column_text(stmt, 1));
        if (name) strcpy(name, (const char*)sqlite3_column_text(stmt, 2));
        if (surname) strcpy(surname, (const char*)sqlite3_column_text(stmt, 3));
        if (password) strcpy(password, (const char*)sqlite3_column_text(stmt, 4));
        if (salt) strcpy(salt, (const char*)sqlite3_column_text(stmt, 5));
        if (privilege) *privilege = sqlite3_column_int(stmt, 6);
        if (created_at) strcpy(created_at, (const char*)sqlite3_column_text(stmt, 7));
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

/**
 * @brief USERS tablosunda kullanıcıyı username ile seçer
 * @details Verilen kullanıcı adı ile USERS tablosundan kullanıcıyı çeker.
 *
 * @param username Kullanıcı adı
 * @param id [OUT] Kullanıcı ID'si
 * @param unit_id [OUT] Bağlı olduğu unit'in ID'si
 * @param name [OUT] Adı
 * @param surname [OUT] Soyadı
 * @param password [OUT] Hashlenmiş şifre
 * @param salt [OUT] Kullanıcıya ait salt
 * @param privilege [OUT] Yetki seviyesi
 * @param created_at [OUT] Oluşturulma zamanı
 * @return int 0: Başarılı, -1: Hata veya kullanıcı yok
 */
int db_select_user_by_username(const char *username, int *id, int *unit_id, char *name, char *surname, char *password, char *salt, int *privilege, char *created_at) {
    char sql[256];
    sqlite3_stmt *stmt;
    int rc;
    snprintf(sql, sizeof(sql), "SELECT ID, UNIT_ID, NAME, SURNAME, PASSWORD, SALT, PRIVILEGE, CREATED_AT FROM USERS WHERE USERNAME = ?;");
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error preparing select user: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (id) *id = sqlite3_column_int(stmt, 0);
        if (unit_id) *unit_id = sqlite3_column_int(stmt, 1);
        if (name) strcpy(name, (const char*)sqlite3_column_text(stmt, 2));
        if (surname) strcpy(surname, (const char*)sqlite3_column_text(stmt, 3));
        if (password) strcpy(password, (const char*)sqlite3_column_text(stmt, 4));
        if (salt) strcpy(salt, (const char*)sqlite3_column_text(stmt, 5));
        if (privilege) *privilege = sqlite3_column_int(stmt, 6);
        if (created_at) strcpy(created_at, (const char*)sqlite3_column_text(stmt, 7));
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

/**
 * @brief USERS tablosunda id ile kullanıcıyı bulur, yoksa oluşturur
 * @param id Kullanıcı ID'si
 * @param unit_id Birim ID
 * @param username Kullanıcı adı
 * @param name Adı
 * @param surname Soyadı
 * @param password Hashlenmiş şifre
 * @param salt Salt
 * @param privilege Yetki seviyesi
 * @return int Kullanıcı ID'si veya hata (-1)
 */
int db_find_or_create_user_by_id(int id, int unit_id, const char* username, const char* name, const char* surname, const char* password, const char* salt, int privilege) {
    char dummy_username[32] = "";
    char dummy_name[32] = "";
    char dummy_surname[32] = "";
    char dummy_password[129] = "";
    char dummy_salt[17] = "";
    int dummy_privilege = 0;
    char dummy_created_at[32] = "";
    int dummy_unit_id = 0;
    int rc = db_select_user_by_id(id, &dummy_unit_id, dummy_username, dummy_name, dummy_surname, dummy_password, dummy_salt, &dummy_privilege, dummy_created_at);
    if (rc == 0) {
        return id;
    } else {
        return db_insert_user(unit_id, username, name, surname, password, salt, privilege);
    }
}

/**
 * @brief USERS tablosunda username ile kullanıcıyı bulur, yoksa oluşturur
 * @param username Kullanıcı adı
 * @param unit_id Birim ID
 * @param name Adı
 * @param surname Soyadı
 * @param password Hashlenmiş şifre
 * @param salt Salt
 * @param privilege Yetki seviyesi
 * @return int Kullanıcı ID'si veya hata (-1)
 */
int db_find_or_create_user_by_username(const char* username, int unit_id, const char* name, const char* surname, const char* password, const char* salt, int privilege) {
    int id = -1;
    int dummy_unit_id = 0;
    char dummy_name[32] = "";
    char dummy_surname[32] = "";
    char dummy_password[129] = "";
    char dummy_salt[17] = "";
    int dummy_privilege = 0;
    char dummy_created_at[32] = "";
    int rc = db_select_user_by_username(username, &id, &dummy_unit_id, dummy_name, dummy_surname, dummy_password, dummy_salt, &dummy_privilege, dummy_created_at);
    if (rc == 0 && id > 0) {
        return id;
    } else {
        return db_insert_user(unit_id, username, name, surname, password, salt, privilege);
    }
}

char* login_user_with_argon2(const char *username, const char *password) {
    int id = -1;
    int unit_id = 0;
    char name[32] = "";
    char surname[32] = "";
    char stored_password[129] = "";
    char salt[17] = "";
    int privilege = 0;
    char created_at[32] = "";

    // Kullanıcıyı username ile bul
    int rc = db_select_user_by_username(username, &id, &unit_id, name, surname, stored_password, salt, &privilege, created_at);
    if (rc != 0 || id <= 0) {
        return NULL; // Kullanıcı bulunamadı
    }

    // Şifreyi Argon2 ile doğrula
    if (verify_password_with_salt(password, salt, stored_password) != 0) {
        return NULL; // Şifre yanlış
    }

    // Artık user_id olarak username'i JWT'ye ekle
    char user_id_str[32];
    snprintf(user_id_str, sizeof(user_id_str), "%d", id);
    return generate_jwt(user_id_str, name, surname, privilege); // JWT token'ı döner
}