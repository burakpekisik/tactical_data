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
#include "database.h"
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

/**
 * @brief CHAT_ROOMS tablosunda belirli ID'ye sahip odayı günceller
 * @details Verilen ID'ye sahip chat odası kaydının belirli alanlarını günceller.
 *          CREATED_AT alanı korunur, diğer alanlar güncellenebilir.
 * 
 * Güncellenebilen Alanlar:
 * - ROOM_NAME (string)
 * - ROOM_TYPE (integer)
 * - DESCRIPTION (string, nullable)
 * - CURRENT_USERS (integer)
 * - ALLOWED_USER_IDS (string, CSV format)
 * - IS_ACTIVE (integer boolean)
 * 
 * @param room_id Güncellenecek chat odasının ID'si
 * @param room_name Yeni oda adı
 * @param room_type Yeni oda tipi (0=everyone, 1=admin_only, 2=specific_users)
 * @param description Yeni açıklama (NULL olabilir)
 * @param current_users Mevcut kullanıcı sayısı
 * @param allowed_user_ids İzinli kullanıcı listesi (CSV format)
 * @param is_active Aktiflik durumu (0 veya 1)
 * @return int İşlem sonucu
 * @retval 0 Başarılı güncelleme
 * @retval -1 Güncelleme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning String alanlarında SQL injection koruması yok
 * @warning room_id geçerli bir chat room ID'si olmalıdır
 * 
 * @see db_insert_chat_room(), db_select_chat_room_by_id()
 */
int db_update_chat_room(int room_id, const char* room_name, int room_type, 
                       const char* description, int current_users, 
                       const char* allowed_user_ids, int is_active) {
    char *zErrMsg = 0;
    char sql[2048];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    if (!room_name || !allowed_user_ids) {
        fprintf(stderr, "Required parameters cannot be NULL\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE chat_rooms SET room_name='%s', room_type=%d, description='%s', "
        "current_users=%d, allowed_user_ids='%s', is_active=%d WHERE room_id=%d;",
        room_name, room_type, description ? description : "",
        current_users, allowed_user_ids, is_active, room_id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating chat room: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat room ID %d updated successfully\n", room_id);
            return 0;
        } else {
            PRINTF_LOG("No chat room found with ID %d\n", room_id);
            return -1;
        }
    }
}

/**
 * @brief Chat odasının kullanıcı sayısını günceller
 * @details Verilen chat odası ID'sine sahip odanın mevcut kullanıcı sayısını günceller.
 *          Bu fonksiyon kullanıcı katılım/ayrılma işlemlerinde kullanılır.
 * 
 * @param room_id Güncellenecek chat odasının ID'si
 * @param current_users Yeni kullanıcı sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı güncelleme
 * @retval -1 Güncelleme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note Bu fonksiyon sadece current_users alanını günceller
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning room_id geçerli bir chat room ID'si olmalıdır
 * @warning current_users negatif olamaz
 * 
 * @see db_update_chat_room(), db_select_chat_room_by_id()
 */
int db_update_chat_room_users(int room_id, int current_users) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    if (current_users < 0) {
        fprintf(stderr, "Current users cannot be negative\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE chat_rooms SET current_users=%d WHERE room_id=%d;",
        current_users, room_id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating chat room users: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat room ID %d user count updated to %d\n", room_id, current_users);
            return 0;
        } else {
            PRINTF_LOG("No chat room found with ID %d\n", room_id);
            return -1;
        }
    }
}

/**
 * @brief Chat odasının aktiflik durumunu günceller
 * @details Verilen chat odası ID'sine sahip odanın aktiflik durumunu günceller.
 *          Bu fonksiyon oda devre dışı bırakma (soft delete) için kullanılır.
 * 
 * @param room_id Güncellenecek chat odasının ID'si
 * @param is_active Yeni aktiflik durumu (0=inactive, 1=active)
 * @return int İşlem sonucu
 * @retval 0 Başarılı güncelleme
 * @retval -1 Güncelleme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note Bu fonksiyon sadece is_active alanını günceller
 * @note Soft delete için is_active=0 kullanılır
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning room_id geçerli bir chat room ID'si olmalıdır
 * @warning is_active 0 veya 1 olmalıdır
 * 
 * @see db_delete_chat_room(), db_update_chat_room()
 */
int db_update_chat_room_status(int room_id, int is_active) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    if (is_active != 0 && is_active != 1) {
        fprintf(stderr, "is_active must be 0 or 1\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE chat_rooms SET is_active=%d WHERE room_id=%d;",
        is_active, room_id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating chat room status: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat room ID %d status updated to %s\n", 
                      room_id, is_active ? "active" : "inactive");
            return 0;
        } else {
            PRINTF_LOG("No chat room found with ID %d\n", room_id);
            return -1;
        }
    }
}

/**
 * @brief CHAT_MESSAGES tablosunda mesaj günceller (teorik - normalde gerekmiyor)
 * @details Chat mesajları genellikle güncellenmez ancak özel durumlar için
 *          (moderasyon, düzenleme) bu fonksiyon kullanılabilir.
 * 
 * @param message_id Güncellenecek mesajın ID'si
 * @param content Yeni mesaj içeriği
 * @param is_edited Düzenlenme durumu (0 veya 1)
 * @return int İşlem sonucu
 * @retval 0 Başarılı güncelleme
 * @retval -1 Güncelleme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note Chat mesajları normalde güncellenmez
 * @note Bu fonksiyon moderasyon veya düzenleme için kullanılabilir
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning message_id geçerli bir chat message ID'si olmalıdır
 * @warning content NULL olamaz
 * 
 * @see db_insert_chat_message(), db_delete_chat_message()
 */
int db_update_chat_message(int message_id, const char* content, int is_edited) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    if (!content) {
        fprintf(stderr, "Message content cannot be NULL\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "UPDATE chat_messages SET content='%s', is_edited=%d WHERE message_id=%d;",
        content, is_edited, message_id);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error updating chat message: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat message ID %d updated successfully\n", message_id);
            return 0;
        } else {
            PRINTF_LOG("No chat message found with ID %d\n", message_id);
            return -1;
        }
    }
}