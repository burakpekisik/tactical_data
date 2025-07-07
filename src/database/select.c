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
#include "database.h"
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
 * @brief REPLIES tablosu callback fonksiyonu
 * @details sqlite3_exec() tarafından çağrılan callback. Her reply record'u için
 *          çağrılır ve dynamic array'e reply verilerini ekler.
 *
 * Callback Data Formatı:
 * - data[0]: reply_t** (replies array pointer)
 * - data[1]: int* (current count)
 * - data[2]: int* (array capacity)
 *
 * @param data Callback veri paketi (reply array, count, capacity)
 * @param argc Column sayısı
 * @param argv Column değerleri array'i
 * @param azColName Column isimleri array'i
 * @return int Callback sonucu (0: devam, non-zero: abort)
 *
 * @note Dynamic memory reallocation yapabilir
 * @note NULL değerler güvenli şekilde handle edilir
 * @warning Buffer overflow koruması için strncpy kullanılır
 */
static int reply_callback(void *data, int argc, char **argv, char **azColName) {
    reply_t **replies = (reply_t **)((void**)data)[0];
    int *count = (int *)((void**)data)[1];
    int *capacity = (int *)((void**)data)[2];

    if (*count >= *capacity) {
        *capacity *= 2;
        *replies = realloc(*replies, *capacity * sizeof(reply_t));
    }

    reply_t *reply = &(*replies)[*count];
    memset(reply, 0, sizeof(reply_t));

    for(int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "ID") == 0 && argv[i]) {
            reply->id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "USER_ID") == 0 && argv[i]) {
            reply->user_id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "REPORT_ID") == 0 && argv[i]) {
            reply->report_id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "MESSAGE") == 0 && argv[i]) {
            strncpy(reply->message, argv[i], sizeof(reply->message) - 1);
        } else if (strcmp(azColName[i], "TIMESTAMP") == 0 && argv[i]) {
            reply->timestamp = atol(argv[i]);
        } else if (strcmp(azColName[i], "CREATED_AT") == 0 && argv[i]) {
            strncpy(reply->created_at, argv[i], sizeof(reply->created_at) - 1);
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

int db_select_replies_by_user(int user_id, reply_t **replies, int *count) {
    char *zErrMsg = 0;
    char sql[512];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    // JOIN kullanarak kullanıcının raporlarına gelen reply'ları çek
    snprintf(sql, sizeof(sql), 
        "SELECT r.ID, r.USER_ID, r.REPORT_ID, r.MESSAGE, r.TIMESTAMP "
        "FROM REPLIES r "
        "JOIN REPORTS rep ON r.REPORT_ID = rep.ID "
        "WHERE rep.USER_ID = %d "
        "ORDER BY r.TIMESTAMP DESC", user_id);

    *count = 0;
    int capacity = 10;
    *replies = malloc(capacity * sizeof(reply_t));

    void *callback_data[] = {replies, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, reply_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting replies by user: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*replies);
        return -1;
    }

    return 0;
}

int db_select_replies_by_report(int report_id, reply_t **replies, int *count) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), 
        "SELECT * FROM REPLIES WHERE REPORT_ID = %d ORDER BY TIMESTAMP DESC", report_id);

    *count = 0;
    int capacity = 10;
    *replies = malloc(capacity * sizeof(reply_t));

    void *callback_data[] = {replies, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, reply_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting replies by report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*replies);
        return -1;
    }

    return 0;
}

/**
 * @brief Kullanıcının raporlarına gelen reply'ları JOIN kullanarak sorgular
 * @details REPLIES ve REPORTS tablolarını JOIN ederek belirli bir kullanıcının
 *          raporlarına gelen tüm admin cevaplarını getirir.
 * 
 * SQL Sorgusu:
 * SELECT r.* FROM REPLIES r 
 * JOIN REPORTS rep ON r.report_id = rep.id 
 * WHERE rep.user_id = ? 
 * ORDER BY r.timestamp DESC
 * 
 * @param user_id Kullanıcı ID'si
 * @param replies [OUT] Reply array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen reply sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama
 * @retval -1 Sorgu hatası
 * 
 * @note replies array'i çağıran tarafından free() edilmelidir
 * @warning replies ve count pointer'ları NULL olmamalıdır
 */
int db_select_replies_for_user_reports(int user_id, reply_t **replies, int *count) {
    char *zErrMsg = 0;
    int rc;
    char sql[512];

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), 
        "SELECT r.id, r.user_id, r.report_id, r.message, r.timestamp, r.created_at "
        "FROM REPLIES r "
        "JOIN REPORTS rep ON r.report_id = rep.id " 
        "WHERE rep.user_id = %d "
        "ORDER BY r.timestamp DESC", user_id);

    *count = 0;
    int capacity = 10;
    *replies = malloc(capacity * sizeof(reply_t));

    void *callback_data[] = {replies, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, reply_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting replies for user reports: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*replies);
        return -1;
    }

    return 0;
}

/**
 * @brief ID'ye göre tek bir raporu getirir
 * @details Verilen ID'ye sahip raporu REPORTS tablosundan getirir.
 *          Güvenlik kontrollerinde kullanılır.
 * 
 * @param id Getirilecek raporun ID'si
 * @param report Rapor bilgilerinin yazılacağı report_t yapısı
 * @return 0 başarı durumunda, -1 hata durumunda
 * 
 * @note Rapor bulunamazsa -1 döndürür
 * @warning report parametresi NULL olmamalıdır
 */
int db_get_report_by_id(int id, report_t *report) {
    if (!report) {
        fprintf(stderr, "Hata: report parametresi NULL\n");
        return -1;
    }
    
    if (!g_db) {
        fprintf(stderr, "Veritabanı bağlantısı yok\n");
        return -1;
    }
    
    char sql[512];
    snprintf(sql, sizeof(sql), 
        "SELECT id, user_id, status, latitude, longitude, description, timestamp, created_at "
        "FROM REPORTS WHERE id = %d", id);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare hatası: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }
    
    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        // Rapor bulundu, verileri kopyala
        report->id = sqlite3_column_int(stmt, 0);
        report->user_id = sqlite3_column_int(stmt, 1);
        
        const char* status = (const char*)sqlite3_column_text(stmt, 2);
        if (status) {
            strncpy(report->status, status, sizeof(report->status) - 1);
            report->status[sizeof(report->status) - 1] = '\0';
        } else {
            strcpy(report->status, "UNKNOWN");
        }
        
        report->latitude = sqlite3_column_double(stmt, 3);
        report->longitude = sqlite3_column_double(stmt, 4);
        
        const char* description = (const char*)sqlite3_column_text(stmt, 5);
        if (description) {
            strncpy(report->description, description, sizeof(report->description) - 1);
            report->description[sizeof(report->description) - 1] = '\0';
        } else {
            strcpy(report->description, "Açıklama yok");
        }
        
        report->timestamp = sqlite3_column_int64(stmt, 6);
        
        const char* created_at = (const char*)sqlite3_column_text(stmt, 7);
        if (created_at) {
            strncpy(report->created_at, created_at, sizeof(report->created_at) - 1);
            report->created_at[sizeof(report->created_at) - 1] = '\0';
        } else {
            strcpy(report->created_at, "");
        }
        
        sqlite3_finalize(stmt);
        return 0; // Başarılı
    } else if (rc == SQLITE_DONE) {
        // Rapor bulunamadı
        sqlite3_finalize(stmt);
        return -1;
    } else {
        // SQL hatası
        fprintf(stderr, "SQL step hatası: %s\n", sqlite3_errmsg(g_db));
        sqlite3_finalize(stmt);
        return -1;
    }
}

/**
 * @brief Chat odalarını ID'ye göre sorgula
 * @details CHAT_ROOMS tablosundan ID'ye göre oda bilgilerini getirir
 * 
 * @param room_id Oda ID'si
 * @param room Sonuç oda verisi (chat_room_t struct pointer)
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgu
 * @retval -1 Sorgu hatası veya bulunamadı
 */
int db_select_chat_room_by_id(int room_id, chat_room_t *room) {
    char sql[512];
    sqlite3_stmt *stmt;
    int rc;

    if (!g_db || !room || room_id <= 0) {
        fprintf(stderr, "Invalid parameters for chat room select\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "SELECT room_id, room_name, creator_id, room_type, max_users, "
        "current_users, allowed_user_ids, room_key, created_at, is_active "
        "FROM chat_rooms WHERE room_id = %d AND is_active = 1;", room_id);

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memset(room, 0, sizeof(chat_room_t));
        
        room->room_id = sqlite3_column_int(stmt, 0);
        strncpy(room->room_name, (const char*)sqlite3_column_text(stmt, 1), sizeof(room->room_name) - 1);
        strncpy(room->creator_id, (const char*)sqlite3_column_text(stmt, 2), sizeof(room->creator_id) - 1);
        room->room_type = (chat_room_type_t)sqlite3_column_int(stmt, 3);
        room->max_users = sqlite3_column_int(stmt, 4);
        room->current_users = sqlite3_column_int(stmt, 5);
        
        const char* allowed_users = (const char*)sqlite3_column_text(stmt, 6);
        if (allowed_users) {
            strncpy(room->allowed_user_ids, allowed_users, sizeof(room->allowed_user_ids) - 1);
        }
        
        const char* room_key_hex = (const char*)sqlite3_column_text(stmt, 7);
        if (room_key_hex && strlen(room_key_hex) == ROOM_KEY_SIZE * 2) {
            // Hex string'i binary'ye çevir
            for (int i = 0; i < ROOM_KEY_SIZE; i++) {
                sscanf(room_key_hex + (i * 2), "%2hhx", &room->room_key[i]);
            }
        }
        
        room->created_at = sqlite3_column_int64(stmt, 8);
        room->is_active = sqlite3_column_int(stmt, 9) == 1;
        
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_DONE) {
        return -1; // Bulunamadı
    }
    
    fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(g_db));
    return -1;
}

/**
 * @brief Kullanıcının erişebileceği chat odalarını listele
 * @details Kullanıcı privilege'ine göre erişilebilir odaları getirir
 * 
 * @param user_id Kullanıcı ID'si
 * @param user_privilege Kullanıcı privilege seviyesi
 * @param rooms Sonuç odalar array'i (malloc edilir)
 * @param count Sonuç oda sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgu
 * @retval -1 Sorgu hatası
 */
int db_select_user_accessible_chat_rooms(const char* user_id, int user_privilege, 
                                        chat_room_t** rooms, int* count) {
    char sql[1024];
    sqlite3_stmt *stmt;
    int rc;
    *rooms = NULL;
    *count = 0;

    if (!g_db || !user_id || !rooms || !count) {
        fprintf(stderr, "Invalid parameters for accessible rooms select\n");
        return -1;
    }

    // SQL sorgusu - kullanıcının erişebileceği odalar
    snprintf(sql, sizeof(sql),
        "SELECT room_id, room_name, creator_id, room_type, max_users, "
        "current_users, allowed_user_ids, room_key, created_at, is_active "
        "FROM chat_rooms WHERE is_active = 1 AND ("
        "room_type = 0 OR " // ROOM_TYPE_EVERYONE
        "(room_type = 1 AND %d = 1) OR " // ROOM_TYPE_ADMIN_ONLY ve user admin ise
        "(room_type = 2 AND (allowed_user_ids LIKE '%%%s%%' OR creator_id = '%s'))" // ROOM_TYPE_SPECIFIC_USERS
        ") ORDER BY created_at DESC;",
        user_privilege, user_id, user_id);

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // Önce kaç oda olduğunu say
    int room_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        room_count++;
    }

    // Statement'i sıfırla
    sqlite3_reset(stmt);

    if (room_count > 0) {
        *rooms = malloc(sizeof(chat_room_t) * room_count);
        if (!*rooms) {
            fprintf(stderr, "Memory allocation failed for rooms array\n");
            sqlite3_finalize(stmt);
            return -1;
        }

        int index = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && index < room_count) {
            chat_room_t* room = &(*rooms)[index];
            memset(room, 0, sizeof(chat_room_t));

            room->room_id = sqlite3_column_int(stmt, 0);
            strncpy(room->room_name, (const char*)sqlite3_column_text(stmt, 1), sizeof(room->room_name) - 1);
            strncpy(room->creator_id, (const char*)sqlite3_column_text(stmt, 2), sizeof(room->creator_id) - 1);
            room->room_type = (chat_room_type_t)sqlite3_column_int(stmt, 3);
            room->max_users = sqlite3_column_int(stmt, 4);
            room->current_users = sqlite3_column_int(stmt, 5);

            const char* allowed_users = (const char*)sqlite3_column_text(stmt, 6);
            if (allowed_users) {
                strncpy(room->allowed_user_ids, allowed_users, sizeof(room->allowed_user_ids) - 1);
            }

            const char* room_key_hex = (const char*)sqlite3_column_text(stmt, 7);
            if (room_key_hex && strlen(room_key_hex) == ROOM_KEY_SIZE * 2) {
                for (int i = 0; i < ROOM_KEY_SIZE; i++) {
                    sscanf(room_key_hex + (i * 2), "%2hhx", &room->room_key[i]);
                }
            }

            room->created_at = sqlite3_column_int64(stmt, 8);
            room->is_active = sqlite3_column_int(stmt, 9) == 1;

            index++;
        }
    }

    *count = room_count;
    sqlite3_finalize(stmt);
    PRINTF_LOG("Found %d accessible chat rooms for user %s\n", room_count, user_id);
    return 0;
}

/**
 * @brief Oda mesajlarını getir (sayfalama ile)
 * @details CHAT_MESSAGES tablosundan oda mesajlarını getirir
 * 
 * @param room_id Oda ID'si
 * @param messages Sonuç mesajlar array'i (malloc edilir)
 * @param count Sonuç mesaj sayısı
 * @param limit Maksimum mesaj sayısı
 * @param offset Başlangıç offset'i
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgu
 * @retval -1 Sorgu hatası
 */
int db_select_chat_room_messages(int room_id, int limit, chat_message_t** messages, int* count) {
    char sql[512];
    sqlite3_stmt *stmt;
    int rc;
    *messages = NULL;
    *count = 0;

    if (!g_db || room_id <= 0 || !messages || !count) {
        fprintf(stderr, "Invalid parameters for room messages select\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "SELECT message_id, room_id, sender_id, sender_name, message, timestamp "
        "FROM chat_messages WHERE room_id = %d "
        "ORDER BY timestamp DESC LIMIT %d;",
        room_id, limit);

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // Önce kaç mesaj olduğunu say
    int message_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        message_count++;
    }

    sqlite3_reset(stmt);

    if (message_count > 0) {
        *messages = malloc(sizeof(chat_message_t) * message_count);
        if (!*messages) {
            fprintf(stderr, "Memory allocation failed for messages array\n");
            sqlite3_finalize(stmt);
            return -1;
        }

        int index = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && index < message_count) {
            chat_message_t* msg = &(*messages)[index];
            memset(msg, 0, sizeof(chat_message_t));

            msg->message_id = sqlite3_column_int(stmt, 0);
            msg->room_id = sqlite3_column_int(stmt, 1);
            strncpy(msg->sender_id, (const char*)sqlite3_column_text(stmt, 2), sizeof(msg->sender_id) - 1);
            strncpy(msg->sender_name, (const char*)sqlite3_column_text(stmt, 3), sizeof(msg->sender_name) - 1);
            strncpy(msg->message, (const char*)sqlite3_column_text(stmt, 4), sizeof(msg->message) - 1);
            msg->timestamp = sqlite3_column_int64(stmt, 5);

            index++;
        }
    }

    *count = message_count;
    sqlite3_finalize(stmt);
    return 0;
}

/**
 * @brief En son mesajları al (chat_get_messages için alias)
 */
int db_chat_get_latest_messages(int room_id, chat_message_t** messages, int* count, int limit) {
    return db_select_chat_room_messages(room_id, limit, messages, count);
}

int db_select_location_of_user(int user_id, double *latitude, double *longitude) {
    char sql[256];
    sqlite3_stmt *stmt;
    int rc;

    if (!g_db || user_id <= 0 || !latitude || !longitude) {
        fprintf(stderr, "Invalid parameters for user location select\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), 
        "SELECT latitude, longitude FROM LOCATIONS WHERE user_id = %d ORDER BY timestamp DESC LIMIT 1;", user_id);

    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *latitude = sqlite3_column_double(stmt, 0);
        *longitude = sqlite3_column_double(stmt, 1);
        sqlite3_finalize(stmt);
        return 0; // Başarılı
    } else if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1; // Kullanıcı bulunamadı
    } else {
        fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(g_db));
        sqlite3_finalize(stmt);
        return -1; // Hata
    }
}

/**
 * @brief Bir unit içindeki tüm kullanıcıların en güncel konumlarını getirir
 * @details Her kullanıcı için LOCATIONS tablosundaki en güncel (timestamp'e göre) kaydı döndürür
 *
 * @param unit_id Unit ID
 * @param locations [OUT] location_t array (malloc edilir, count kadar)
 * @param count [OUT] Kullanıcı sayısı (veya konum kaydı sayısı)
 * @return int 0: Başarılı, -1: Hata
 *
 * @note locations array'i çağıran tarafından free() edilmelidir
 */
int db_select_latest_locations_by_unit(int unit_id, location_t **locations, int *count) {
    if (!g_db || unit_id <= 0 || !locations || !count) {
        fprintf(stderr, "Invalid parameters for latest locations by unit\n");
        return -1;
    }
    *locations = NULL;
    *count = 0;

    const char *sql =
        "SELECT l.id, l.user_id, l.latitude, l.longitude, l.timestamp "
        "FROM LOCATIONS l "
        "JOIN USERS u ON l.user_id = u.ID "
        "WHERE u.UNIT_ID = ? "
        "AND l.id = ( "
        "    SELECT id FROM LOCATIONS "
        "    WHERE user_id = l.user_id "
        "    ORDER BY timestamp DESC LIMIT 1 "
        ") ";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }
    sqlite3_bind_int(stmt, 1, unit_id);

    // Önce kaç kayıt var say
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        row_count++;
    }
    sqlite3_reset(stmt);

    if (row_count > 0) {
        *locations = malloc(sizeof(location_t) * row_count);
        if (!*locations) {
            fprintf(stderr, "Memory allocation failed for locations array\n");
            sqlite3_finalize(stmt);
            return -1;
        }
        int idx = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && idx < row_count) {
            location_t *loc = &(*locations)[idx];
            loc->id = sqlite3_column_int(stmt, 0);
            loc->user_id = sqlite3_column_int(stmt, 1);
            loc->latitude = sqlite3_column_double(stmt, 2);
            loc->longitude = sqlite3_column_double(stmt, 3);
            loc->timestamp = sqlite3_column_int64(stmt, 4);
            idx++;
        }
        *count = row_count;
    }
    sqlite3_finalize(stmt);
    return 0;
}

/**
 * @brief Tüm unique kullanıcılar için en güncel konumları döndürür
 * @details LOCATIONS tablosundaki her user_id için en güncel (timestamp'e göre) kaydı döndürür
 *
 * @param locations [OUT] location_t array (malloc edilir, count kadar)
 * @param count [OUT] Kullanıcı sayısı (veya konum kaydı sayısı)
 * @return int 0: Başarılı, -1: Hata
 *
 * @note locations array'i çağıran tarafından free() edilmelidir
 */
int db_select_latest_locations_all_users(location_t **locations, int *count) {
    if (!g_db || !locations || !count) {
        fprintf(stderr, "Invalid parameters for latest locations all users\n");
        return -1;
    }
    *locations = NULL;
    *count = 0;

    const char *sql =
        "SELECT l.id, l.user_id, l.latitude, l.longitude, l.timestamp "
        "FROM LOCATIONS l "
        "WHERE l.id = ( "
        "    SELECT id FROM LOCATIONS "
        "    WHERE user_id = l.user_id "
        "    ORDER BY timestamp DESC LIMIT 1 "
        ") ";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // Önce kaç kayıt var say
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        row_count++;
    }
    sqlite3_reset(stmt);

    if (row_count > 0) {
        *locations = malloc(sizeof(location_t) * row_count);
        if (!*locations) {
            fprintf(stderr, "Memory allocation failed for locations array\n");
            sqlite3_finalize(stmt);
            return -1;
        }
        int idx = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && idx < row_count) {
            location_t *loc = &(*locations)[idx];
            loc->id = sqlite3_column_int(stmt, 0);
            loc->user_id = sqlite3_column_int(stmt, 1);
            loc->latitude = sqlite3_column_double(stmt, 2);
            loc->longitude = sqlite3_column_double(stmt, 3);
            loc->timestamp = sqlite3_column_int64(stmt, 4);
            idx++;
        }
        *count = row_count;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int db_select_latest_locations_all_users_by_radius(double latitude, double longitude, double radius, location_t **locations, int *count) {
    if (!g_db || !locations || !count) {
        fprintf(stderr, "Invalid parameters for latest locations by radius\n");
        return -1;
    }
    *locations = NULL;
    *count = 0;

    const char *sql =
        "SELECT l.id, l.user_id, l.latitude, l.longitude, l.timestamp "
        "FROM LOCATIONS l "
        "WHERE l.id = ( "
        "    SELECT id FROM LOCATIONS "
        "    WHERE user_id = l.user_id "
        "    ORDER BY timestamp DESC LIMIT 1 "
        ") AND ("
        "    (l.latitude - ?) * (l.latitude - ?) + "
        "    (l.longitude - ?) * (l.longitude - ?) <= ? * ?"
        ")";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_double(stmt, 1, latitude);
    sqlite3_bind_double(stmt, 2, latitude);
    sqlite3_bind_double(stmt, 3, longitude);
    sqlite3_bind_double(stmt, 4, longitude);
    sqlite3_bind_double(stmt, 5, radius);
    sqlite3_bind_double(stmt, 6, radius);

    // Önce kaç kayıt var say
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        row_count++;
    }
    sqlite3_reset(stmt);

    if (row_count > 0) {
        *locations = malloc(sizeof(location_t) * row_count);
        if (!*locations) {
            fprintf(stderr, "Memory allocation failed for locations array\n");
            sqlite3_finalize(stmt);
            return -1;
        }
        int idx = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && idx < row_count) {
            location_t *loc = &(*locations)[idx];
            loc->id = sqlite3_column_int(stmt, 0);
            loc->user_id = sqlite3_column_int(stmt, 1);
            loc->latitude = sqlite3_column_double(stmt, 2);
            loc->longitude = sqlite3_column_double(stmt, 3);
            loc->timestamp = sqlite3_column_int64(stmt, 4);
            idx++;
        }
        *count = row_count;
    }
    sqlite3_finalize(stmt);
    return 0;
}