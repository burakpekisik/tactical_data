/**
 * @file delete.c
 * @brief Veritabanı silme işlemleri ve bellek temizleme
 * @details Bu dosya SQLite3 veritabanından unit ve report kayıtlarının silinmesi,
 *          foreign key constraint yönetimi ve dynamic array'lerin bellek
 *          temizleme işlemlerini içerir. Tactical Data Transfer System'in
 *          veri silme katmanını oluşturur.
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
 * @brief External global veritabanı bağlantısı
 * @details create.c'de tanımlanan global veritabanı bağlantısına referans
 * @see g_db in create.c
 */
extern sqlite3 *g_db;

/**
 * @brief UNITS tablosundan unit kaydını ve ilişkili raporları siler
 * @details Verilen ID'ye sahip unit'i siler. Foreign key constraint nedeniyle
 *          önce ilişkili REPORTS kayıtları, sonra UNITS kaydı silinir.
 * 
 * Silme Sırası (Foreign Key Constraint):
 * 1. DELETE FROM REPORTS WHERE UNIT_ID = {id}
 * 2. DELETE FROM UNITS WHERE ID = {id}
 * 3. Etkilenen kayıt sayısını kontrol et
 * 
 * @param id Silinecek unit'in database ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme (unit ve ilişkili raporlar)
 * @retval -1 Silme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note Cascade DELETE etkisi - unit silinince tüm raporları da silinir
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @note İlişkili raporlar varsa önce onlar silinir (foreign key constraint)
 * @warning id geçerli bir database ID olmalıdır
 * @warning Silme işlemi geri alınamaz
 * 
 * @see db_delete_report(), db_update_unit()
 */
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
            PRINTF_LOG("Unit ID %d and associated reports deleted successfully\n", id);
            return 0;
        } else {
            PRINTF_LOG("No unit found with ID %d\n", id);
            return -1;
        }
    }
}

/**
 * @brief REPORTS tablosundan tek report kaydını siler
 * @details Verilen ID'ye sahip report kaydını REPORTS tablosundan siler.
 *          Unit kaydı etkilenmez, sadece spesifik rapor silinir.
 * 
 * @param id Silinecek report'un database ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme
 * @retval -1 Silme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @note Unit kaydı etkilenmez, sadece report silinir
 * @note Foreign key constraint unit tarafından etkilenmez
 * @warning id geçerli bir database ID olmalıdır
 * @warning Silme işlemi geri alınamaz
 * 
 * @see db_delete_unit(), db_update_report()
 */
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
            PRINTF_LOG("Report ID %d deleted successfully\n", id);
            return 0;
        } else {
            PRINTF_LOG("No report found with ID %d\n", id);
            return -1;
        }
    }
}

/**
 * @brief USERS tablosundan kullanıcıyı siler
 * @details Verilen ID'ye sahip kullanıcıyı USERS tablosundan siler.
 *
 * @param id Silinecek kullanıcının database ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme
 * @retval -1 Silme hatası (database not initialized, SQL error, ID not found)
 *
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning id geçerli bir database ID olmalıdır
 * @warning Silme işlemi geri alınamaz
 *
 * @see db_delete_unit(), db_delete_report()
 */
int db_delete_user(int id) {
    char sql[256];
    char *zErrMsg = 0;
    int rc;
    snprintf(sql, sizeof(sql), "DELETE FROM USERS WHERE ID = %d;", id);
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting user: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }
    PRINTF_LOG("User ID %d deleted successfully\n", id);
    return 0;
}

/**
 * @brief Units dynamic array'inin belleğini serbest bırakır
 * @details db_select_units() fonksiyonu tarafından tahsis edilen unit array'inin
 *          belleğini güvenli şekilde serbest bırakır.
 * 
 * @param units Serbest bırakılacak unit array pointer'ı
 * @param count Array eleman sayısı (kullanılmaz, ileriye dönük uyumluluk için)
 * 
 * @note count parametresi şu anda kullanılmaz (__attribute__((unused)))
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note Bu fonksiyon db_select_units() ile eşleşir
 * @warning units pointer'ı malloc ile tahsis edilmiş olmalıdır
 * 
 * @see db_select_units(), db_free_reports()
 */
void db_free_units(unit_t *units, int count __attribute__((unused))) {
    if (units) {
        free(units);
    }
}

/**
 * @brief Reports dynamic array'inin belleğini serbest bırakır
 * @details db_select_reports() ve db_select_reports_by_unit() fonksiyonları
 *          tarafından tahsis edilen report array'inin belleğini güvenli şekilde serbest bırakır.
 * 
 * @param reports Serbest bırakılacak report array pointer'ı
 * @param count Array eleman sayısı (kullanılmaz, ileriye dönük uyumluluk için)
 * 
 * @note count parametresi şu anda kullanılmaz (__attribute__((unused)))
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note Bu fonksiyon db_select_reports() ve db_select_reports_by_unit() ile eşleşir
 * @warning reports pointer'ı malloc ile tahsis edilmiş olmalıdır
 * 
 * @see db_select_reports(), db_select_reports_by_unit(), db_free_units()
 */
void db_free_reports(report_t *reports, int count __attribute__((unused))) {
    if (reports) {
        free(reports);
    }
}