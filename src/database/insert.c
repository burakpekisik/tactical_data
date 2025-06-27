/**
 * @file insert.c
 * @brief Veritabanı veri ekleme işlemleri
 * @details Bu dosya SQLite3 veritabanına unit ve report verilerinin eklenmesi,
 *          JSON'dan gelen tactical data'nın işlenmesi ve otomatik unit oluşturma
 *          işlemlerini içerir. Tactical Data Transfer System'in veri kaydetme
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
#include "../../include/json_utils.h"
#include "../../include/logger.h"
#include "../../include/argon2.h"
#include "../../include/config.h"

/**
 * @brief External global veritabanı bağlantısı
 * @details create.c'de tanımlanan global veritabanı bağlantısına referans
 * @see g_db in create.c
 */
extern sqlite3 *g_db;

/**
 * @brief UNITS tablosuna yeni unit kaydı ekler
 * @details Unit bilgilerini UNITS tablosuna INSERT eder. Auto-increment ID döner.
 *          UNIQUE constraint violation durumunda hata verir.
 * 
 * @param unit Eklenecek unit verisi (unit_t struct pointer)
 * @return int İşlem sonucu
 * @retval >0 Başarılı ekleme, yeni record'un ID'si
 * @retval -1 Ekleme hatası (SQL error, database not initialized)
 * 
 * @note UNIT_ID alanı UNIQUE constraint'e sahiptir
 * @warning unit pointer NULL olmamalıdır
 * @warning String alanlarında SQL injection koruması yok
 * 
 * @todo Prepared statement kullanarak SQL injection koruması ekle
 * @see unit_t, db_init()
 */
int db_insert_unit(const unit_t *unit) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "INSERT INTO UNITS (UNIT_ID, UNIT_NAME, UNIT_TYPE, LOCATION, ACTIVE) "
        "VALUES ('%s', '%s', '%s', '%s', %d);",
        unit->unit_id, unit->unit_name, unit->unit_type, 
        unit->location, unit->active);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error inserting unit: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        PRINTF_LOG("Unit '%s' inserted successfully\n", unit->unit_id);
        return sqlite3_last_insert_rowid(g_db);
    }
}

/**
 * @brief REPORTS tablosuna yeni rapor kaydı ekler
 * @details Report bilgilerini REPORTS tablosuna INSERT eder. Foreign key
 *          constraint ile UNITS tablosuna bağlıdır.
 * 
 * @param report Eklenecek rapor verisi (report_t struct pointer)
 * @return int İşlem sonucu
 * @retval >0 Başarılı ekleme, yeni record'un ID'si
 * @retval -1 Ekleme hatası (SQL error, foreign key violation, database not initialized)
 * 
 * @note UNIT_ID foreign key constraint ile UNITS.ID'ye bağlıdır
 * @note Koordinatlar 6 decimal precision ile saklanır
 * @warning report pointer NULL olmamalıdır
 * @warning unit_id mevcut bir UNITS record'una işaret etmelidir
 * 
 * @see report_t, db_insert_unit()
 */
int db_insert_report(const report_t *report) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "INSERT INTO REPORTS (USER_ID, STATUS, LATITUDE, LONGITUDE, DESCRIPTION, TIMESTAMP) "
        "VALUES (%d, '%s', %.6f, %.6f, '%s', %ld);",
        report->user_id, report->status, report->latitude, report->longitude,
        report->description, report->timestamp);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error inserting report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        PRINTF_LOG("Report for user ID %d inserted successfully\n", report->user_id);
        return sqlite3_last_insert_rowid(g_db);
    }
}

/**
 * @brief JSON'dan gelen tactical data'yı veritabanına kaydeder
 * @details Tactical data struct'ını alır, unit kontrolü yapar ve rapor olarak kaydeder.
 *          Unit mevcut değilse otomatik olarak oluşturur.
 * 
 * İşlem Sırası:
 * 1. Unit ID kontrolü ve otomatik unit oluşturma
 * 2. Report struct hazırlama
 * 3. Database'e report kaydetme
 * 4. Başarı/hata logging
 * 
 * @param tactical_data JSON'dan parse edilen tactical data
 * @return int İşlem sonucu
 * @retval >0 Başarılı kaydetme, report ID'si
 * @retval -1 Kaydetme hatası (NULL data, unit creation failure, insert failure)
 * 
 * @note Unit bulunamazsa otomatik olarak oluşturulur
 * @note Tüm tactical data alanları report'a kopyalanır
 * @warning tactical_data pointer NULL olmamalıdır
 * 
 * @see tactical_data_t, db_find_or_create_unit_by_id(), db_insert_report()
 */
int db_insert_tactical_data_from_json(const tactical_data_t *tactical_data) {
    if (!tactical_data) {
        fprintf(stderr, "Tactical data is NULL\n");
        return -1;
    }

    // 1. Önce user_id'nin database'de olup olmadığını kontrol et
    // (Burada kullanıcıyı bulmak veya oluşturmak için uygun fonksiyon eklenmeli)
    int user_db_id = atoi(tactical_data->user_id);
    if (user_db_id <= 0) {
        fprintf(stderr, "Geçersiz user_id: %s\n", tactical_data->user_id);
        return -1;
    }
    // Kullanıcı gerçekten var mı kontrol et
    char dummy_username[32];
    char dummy_name[32];
    char dummy_surname[32];
    char dummy_password[129];
    char dummy_salt[17];
    int dummy_privilege;
    char dummy_created_at[32];
    int dummy_unit_id;
    int rc = db_select_user_by_id(user_db_id, &dummy_unit_id, dummy_username, dummy_name, dummy_surname, dummy_password, dummy_salt, &dummy_privilege, dummy_created_at);
    if (rc != 0) {
        fprintf(stderr, "user_id %d bulunamadı!\n", user_db_id);
        return -1;
    }

    // 2. Report verilerini hazırla
    report_t report;
    memset(&report, 0, sizeof(report_t));
    report.user_id = user_db_id;
    strncpy(report.status, tactical_data->status, sizeof(report.status) - 1);
    report.latitude = tactical_data->latitude;
    report.longitude = tactical_data->longitude;
    strncpy(report.description, tactical_data->description, sizeof(report.description) - 1);
    report.timestamp = tactical_data->timestamp;

    // 3. Report'u database'e kaydet
    int report_id = db_insert_report(&report);
    if (report_id <= 0) {
        fprintf(stderr, "Failed to insert tactical data report\n");
        return -1;
    }

    PRINTF_LOG("Tactical data saved: User=%s, Status=%s, Location=(%.6f,%.6f)\n",
           tactical_data->user_id, tactical_data->status, 
           tactical_data->latitude, tactical_data->longitude);

    return report_id;
}

/**
 * @brief Unit ID'ye göre arama yapar, bulunamazsa yeni unit oluşturur
 * @details Verilen UNIT_ID string'i ile database'de arama yapar. Bulunursa
 *          ID'sini döner, bulunamazsa otomatik unit oluşturur.
 * 
 * Arama ve Oluşturma Süreci:
 * 1. UNIT_ID ile UNITS tablosunda arama (prepared statement)
 * 2. Bulunursa: Mevcut unit'in ID'sini döndür
 * 3. Bulunamazsa: Varsayılan değerlerle yeni unit oluştur
 * 4. Auto-created unit bilgilerini logla
 * 
 * @param unit_id Aranacak/oluşturulacak unit identifier string'i
 * @return int Unit'in database ID'si
 * @retval >0 Başarılı bulma/oluşturma, unit'in database ID'si
 * @retval -1 Hata (NULL/empty unit_id, SQL error, insert failure)
 * 
 * @note Yeni unit "Auto-created Unit {unit_id}" adıyla oluşturulur
 * @note Varsayılan unit_type: "Tactical", location: "Field", active: 1
 * @note Prepared statement ile SQL injection koruması sağlar
 * @warning unit_id NULL veya empty string olmamalıdır
 * 
 * @see db_insert_unit(), db_insert_tactical_data_from_json()
 */
int db_find_or_create_unit_by_id(const char* unit_id) {
    if (!unit_id || strlen(unit_id) == 0) {
        fprintf(stderr, "Invalid unit_id\n");
        return -1;
    }

    // Önce mevcut unit'i ara
    char sql[512];
    sqlite3_stmt *stmt;
    int rc;

    snprintf(sql, sizeof(sql), "SELECT ID FROM UNITS WHERE UNIT_ID = ?");
    
    rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, unit_id, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Unit bulundu
        int id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        PRINTF_LOG("Existing unit found: %s (ID: %d)\n", unit_id, id);
        return id;
    }
    
    sqlite3_finalize(stmt);

    // Unit bulunamadı, yeni unit oluştur
    unit_t new_unit;
    memset(&new_unit, 0, sizeof(unit_t));
    
    strncpy(new_unit.unit_id, unit_id, sizeof(new_unit.unit_id) - 1);
    snprintf(new_unit.unit_name, sizeof(new_unit.unit_name), "Auto-created Unit %s", unit_id);
    strncpy(new_unit.unit_type, "Tactical", sizeof(new_unit.unit_type) - 1);
    strncpy(new_unit.location, "Field", sizeof(new_unit.location) - 1);
    new_unit.active = 1;

    int new_id = db_insert_unit(&new_unit);
    if (new_id > 0) {
        PRINTF_LOG("New unit created: %s (ID: %d)\n", unit_id, new_id);
    }
    
    return new_id;
}

/**
 * @brief USERS tablosuna yeni kullanıcı ekler
 * @details Kullanıcı bilgilerini USERS tablosuna INSERT eder. Auto-increment ID döner.
 *          UNIQUE constraint violation durumunda hata verir.
 *
 * @param user_id Bağlı olduğu unit'in ID'si (veya NULL)
 * @param username Kullanıcı adı (benzersiz)
 * @param name Kullanıcı adı
 * @param surname Kullanıcı soyadı
 * @param password Şifre (hashlenmiş olarak kaydedilmeli)
 * @param salt Şifre için tuz (salt) değeri
 * @param privilege Yetki seviyesi
 * @return int İşlem sonucu
 * @retval >0 Başarılı ekleme, yeni record'un ID'si
 * @retval -1 Ekleme hatası (SQL error, database not initialized)
 *
 * @note USERNAME alanı UNIQUE constraint'e sahiptir
 * @warning String alanlarında SQL injection koruması yok
 *
 */
int db_insert_user(int unit_id, const char* username, const char* name, const char* surname, const char* password, const char* salt, int privilege) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "INSERT INTO USERS (UNIT_ID, USERNAME, NAME, SURNAME, PASSWORD, SALT, PRIVILEGE) "
        "VALUES (%s, '%s', '%s', '%s', '%s', '%s', %d);",
        unit_id > 0 ? "?" : "NULL", username, name, surname, password, salt, privilege);

    if (unit_id > 0) {
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error preparing user insert: %s\n", sqlite3_errmsg(g_db));
            return -1;
        }
        sqlite3_bind_int(stmt, 1, unit_id);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "SQL error inserting user: %s\n", sqlite3_errmsg(g_db));
            sqlite3_finalize(stmt);
            return -1;
        }
        int user_id = (int)sqlite3_last_insert_rowid(g_db);
        sqlite3_finalize(stmt);
        return user_id;
    } else {
        rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
        if(rc != SQLITE_OK) {
            fprintf(stderr, "SQL error inserting user: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return -1;
        }
        return (int)sqlite3_last_insert_rowid(g_db);
    }
}

/**
 * @brief Tactical data'yı kaydeder ve formatlanmış response döndürür
 * @details Tactical data'yı database'e kaydeder ve client'a gönderilecek
 *          detaylı response mesajı oluşturur. İşlem sonucu ve detayları içerir.
 * 
 * Response İçeriği:
 * - Dosya adı ve işlem zamanı
 * - Tactical data detayları (unit, konum, durum)
 * - Database kaydetme sonucu
 * - Başarı/hata durumu
 * - Report ID (başarılı ise)
 * 
 * @param tactical_data Kaydedilecek tactical data
 * @param filename İşlenen dosya adı (response'da gösterilir)
 * @return char* Formatlanmış response string'i (NULL: bellek hatası)
 * 
 * @note Dönen string free() ile serbest bırakılmalıdır
 * @note Response boyutu 2048 byte ile sınırlıdır
 * @note Description 50 karakter sonrası kesilir ("..." eklenir)
 * @warning tactical_data NULL olmamalıdır
 * 
 * @see db_insert_tactical_data_from_json(), get_current_time()
 */
char* db_save_tactical_data_and_get_response(const tactical_data_t *tactical_data, const char* filename) {
    size_t response_size = 2048;
    char *response = malloc(response_size);
    if (!response) {
        return NULL;
    }

    char *current_time = get_current_time();
    
    // Header bilgileri
    snprintf(response, response_size, 
             "Tactical Data Processing Result\n"
             "===============================\n"
             "File: %s\n"
             "Processing Time: %s\n"
             "Data Saved to Database:\n"
             "-----------------------\n", 
             filename, current_time);
    free(current_time);

    // Tactical data bilgilerini ekle
    char temp[2048]; // Buffer boyutunu artırdık
    snprintf(temp, sizeof(temp),
             "User ID: %s\n"
             "Status: %s\n"
             "Location: %.6f, %.6f\n"
             "Description: %.50s%s\n" // Description'ı kısaltıyoruz
             "Timestamp: %ld\n\n",
             tactical_data->user_id,
             tactical_data->status,
             tactical_data->latitude,
             tactical_data->longitude,
             tactical_data->description,
             strlen(tactical_data->description) > 50 ? "..." : "",
             tactical_data->timestamp);
    
    strncat(response, temp, response_size - strlen(response) - 1);

    // Database'e kaydet
    int result = db_insert_tactical_data_from_json(tactical_data);
    
    if (result > 0) {
        snprintf(temp, sizeof(temp),
                "✓ Database Operation: SUCCESS\n"
                "✓ Report ID: %d\n"
                "✓ Data successfully stored\n",
                result);
    } else {
        snprintf(temp, sizeof(temp),
                "✗ Database Operation: FAILED\n"
                "✗ Error: Could not save to database\n");
    }
    
    strncat(response, temp, response_size - strlen(response) - 1);

    return response;
}

/**
 * @brief Argon2 ile şifre hash'leyerek yeni kullanıcı kaydeder
 * @details Verilen kullanıcı bilgileri ile yeni bir kullanıcı oluşturur.
 *          Şifre Argon2 algoritması ile hash'lenir ve sonuç veritabanına kaydedilir.
 *          Varsayılan yetki seviyesi 0'dır.
 * 
 * @param unit_id Bağlı olduğu unit'in ID'si (veya NULL)
 * @param username Kullanıcı adı (benzersiz)
 * @param name Kullanıcı adı
 * @param surname Kullanıcı soyadı
 * @param password Şifre (düz metin olarak, hash'lenmeden önce)
 * @return int İşlem sonucu
 * @retval 1 Başarılı ekleme
 * @retval -1 Ekleme hatası
 * 
 * @see db_insert_user()
 */
int register_user_with_argon2(int unit_id, const char* username, const char* name, const char* surname, const char* password) {
    char salt[SALT_LENGTH];
    char hash[HASH_LENGTH];
    int result = hash_password_with_salt(password, salt, hash);
    if (result != 0) {
        fprintf(stderr, "Argon2 hash hatası: %d\n", result);
        return -1;
    }
    int privilege = 0; // Default yetki
    int rc = db_insert_user(unit_id, username, name, surname, hash, salt, privilege);
    if (rc < 0) {
        fprintf(stderr, "Kullanıcı ekleme hatası!\n");
        return -1;
    }
    PRINTF_LOG("Kullanıcı '%s' başarıyla kaydedildi.\n", username);
    return 1;
}

int db_insert_reply(const reply_t *reply) {
    char *zErrMsg = 0;
    char sql[1024];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql),
        "INSERT INTO REPLIES (USER_ID, REPORT_ID, MESSAGE, TIMESTAMP) "
        "VALUES (%d, %d, '%s', %ld);",
        reply->user_id, reply->report_id, reply->message, reply->timestamp);

    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error inserting report: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        PRINTF_LOG("Reply for report ID %d inserted successfully\n", reply->report_id);
        return sqlite3_last_insert_rowid(g_db);
    }
}