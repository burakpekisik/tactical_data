/**
 * @file update.c
 * @brief Veritabanı güncelleme ve tek kayıt sorgulama işlemleri
 * @details Bu dosya SQLite3 veritabanında unit ve report kayıtlarının güncellenmesi,
 *          ID'ye göre tek kayıt sorgulama ve prepared statement kullanımı
 *          işlemlerini içerir. Tactical Data Transfer System'in veri güncelleme
 *          katmanını oluşturur.
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

/**
 * @brief External global veritabanı bağlantısı
 * @details create.c'de tanımlanan global veritabanı bağlantısına referans
 * @see g_db in create.c
 */
extern sqlite3 *g_db;

/**
 * @brief UNITS tablosunda belirli ID'ye sahip kaydı günceller
 * @details Verilen ID'ye sahip unit kaydının tüm alanlarını yeni değerlerle günceller.
 *          CREATED_AT alanı korunur, diğer alanlar tamamen değiştirilir.
 * 
 * Güncellenebilen Alanlar:
 * - UNIT_ID (string, unique constraint)
 * - UNIT_NAME (string)
 * - UNIT_TYPE (string)
 * - LOCATION (string, nullable)
 * - ACTIVE (integer boolean)
 * 
 * @param id Güncellenecek unit'in database ID'si
 * @param unit Yeni unit verileri
 * @return int İşlem sonucu
 * @retval 0 Başarılı güncelleme
 * @retval -1 Güncelleme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning unit pointer NULL olmamalıdır
 * @warning UNIT_ID unique constraint violation durumunda hata verir
 * @warning String alanlarında SQL injection koruması yok
 * 
 * @todo Prepared statement kullanarak SQL injection koruması ekle
 * @see unit_t, db_get_unit_by_id()
 */
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
            PRINTF_LOG("Unit ID %d updated successfully\n", id);
            return 0;
        } else {
            PRINTF_LOG("No unit found with ID %d\n", id);
            return -1;
        }
    }
}

/**
 * @brief REPORTS tablosunda belirli ID'ye sahip kaydı günceller
 * @details Verilen ID'ye sahip report kaydının tüm alanlarını yeni değerlerle günceller.
 *          CREATED_AT alanı korunur, diğer alanlar tamamen değiştirilir.
 * 
 * Güncellenebilen Alanlar:
 * - UNIT_ID (integer, foreign key)
 * - STATUS (string)
 * - LATITUDE (double, 6 decimal precision)
 * - LONGITUDE (double, 6 decimal precision)
 * - DESCRIPTION (string, nullable)
 * - TIMESTAMP (long, unix timestamp)
 * 
 * @param id Güncellenecek report'un database ID'si
 * @param report Yeni report verileri
 * @return int İşlem sonucu
 * @retval 0 Başarılı güncelleme
 * @retval -1 Güncelleme hatası (database not initialized, SQL error, ID not found, foreign key violation)
 * 
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @note Koordinatlar %.6f precision ile saklanır
 * @warning report pointer NULL olmamalıdır
 * @warning UNIT_ID foreign key constraint ile validate edilir
 * @warning String alanlarında SQL injection koruması yok
 * 
 * @todo Prepared statement kullanarak SQL injection koruması ekle
 * @see report_t, db_get_report_by_id()
 */
int db_update_report(int id, const report_t *report) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE REPORTS SET USER_ID=%d, STATUS='%s', LATITUDE=%.6f, "
        "LONGITUDE=%.6f, DESCRIPTION='%s', TIMESTAMP=%ld WHERE ID=%d;",
        report->user_id, report->status, report->latitude, report->longitude,
        report->description, report->timestamp, id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Report ID %d updated successfully\n", id);
            return 0;
        } else {
            PRINTF_LOG("No report found with ID %d\n", id);
            return -1;
        }
    }
}

// USERS tablosunda kullanıcıyı günceller
int db_update_user(int id, int unit_id, const char* username, const char* name, const char* surname, const char* password, const char* salt, int privilege) {
    char sql[1024];
    char *zErrMsg = 0;
    int rc;
    snprintf(sql, sizeof(sql),
        "UPDATE USERS SET UNIT_ID=%s, USERNAME='%s', NAME='%s', SURNAME='%s', PASSWORD='%s', SALT='%s', PRIVILEGE=%d WHERE ID=%d;",
        unit_id > 0 ? "?" : "NULL", username, name, surname, password, salt, privilege, id);
    if (unit_id > 0) {
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error preparing user update: %s\n", sqlite3_errmsg(g_db));
            return -1;
        }
        sqlite3_bind_int(stmt, 1, unit_id);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "SQL error updating user: %s\n", sqlite3_errmsg(g_db));
            sqlite3_finalize(stmt);
            return -1;
        }
        sqlite3_finalize(stmt);
    } else {
        rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
        if(rc != SQLITE_OK) {
            fprintf(stderr, "SQL error updating user: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return -1;
        }
    }
    PRINTF_LOG("User ID %d updated successfully\n", id);
    return 0;
}

/**
 * @brief ID'ye göre tek unit kaydını getirir
 * @details Verilen ID'ye sahip unit kaydını UNITS tablosundan getirir.
 *          Prepared statement kullanarak güvenli sorgu yapar.
 * 
 * Prepared Statement Avantajları:
 * - SQL injection koruması
 * - Daha iyi performans
 * - Type-safe parameter binding
 * - Otomatik memory management
 * 
 * @param id Getirilecek unit'in database ID'si
 * @param unit [OUT] Unit verilerinin yazılacağı struct
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama, unit bulundu
 * @retval -1 Sorgu hatası veya unit bulunamadı
 * 
 * @note unit struct'ı memset ile temizlenir
 * @note NULL column değerleri güvenli şekilde handle edilir
 * @note sqlite3_finalize() ile statement otomatik temizlenir
 * @warning unit pointer NULL olmamalıdır
 * @warning id geçerli bir database ID olmalıdır
 * 
 * @see unit_t, db_update_unit(), db_get_report_by_id()
 */
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

/**
 * @brief ID'ye göre tek report kaydını getirir
 * @details Verilen ID'ye sahip report kaydını REPORTS tablosundan getirir.
 *          Prepared statement kullanarak güvenli sorgu yapar.
 * 
 * Prepared Statement Özellikleri:
 * - SQL injection koruması
 * - Type-safe column access
 * - Koordinatlar double precision ile alınır
 * - Timestamp int64 olarak alınır
 * - Automatic memory cleanup
 * 
 * @param id Getirilecek report'un database ID'si
 * @param report [OUT] Report verilerinin yazılacağı struct
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama, report bulundu
 * @retval -1 Sorgu hatası veya report bulunamadı
 * 
 * @note report struct'ı memset ile temizlenir
 * @note NULL column değerleri güvenli şekilde handle edilir
 * @note sqlite3_column_double() koordinatlar için kullanılır
 * @note sqlite3_column_int64() timestamp için kullanılır
 * @warning report pointer NULL olmamalıdır
 * @warning id geçerli bir database ID olmalıdır
 * 
 * @see report_t, db_update_report(), db_get_unit_by_id()
 */
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
        report->user_id = sqlite3_column_int(stmt, 1);
        strncpy(report->status, (char*)sqlite3_column_text(stmt, 2), sizeof(report->status) - 1);
        report->latitude = sqlite3_column_double(stmt, 3);
        report->longitude = sqlite3_column_double(stmt, 4);
        if (sqlite3_column_text(stmt, 5)) {
            strncpy(report->description, (char*)sqlite3_column_text(stmt, 5), sizeof(report->description) - 1);
        }
        report->timestamp = sqlite3_column_int64(stmt, 6);
        
        sqlite3_finalize(stmt);
        return 0;
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }
}