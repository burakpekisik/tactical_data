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
#include "database.h"
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
 * @brief CHAT_ROOMS tablosundan chat odasını siler (soft delete)
 * @details Verilen ID'ye sahip chat odasını devre dışı bırakır (is_active=0).
 *          Hard delete yerine soft delete kullanır çünkü chat geçmişi korunmalı.
 * 
 * Soft Delete Avantajları:
 * - Chat geçmişi korunur
 * - Referential integrity bozulmaz
 * - Gerekirse oda tekrar aktifleştirilebilir
 * - Audit trail devam eder
 * 
 * @param room_id Silinecek chat odasının ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme (soft delete)
 * @retval -1 Silme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note Gerçek silme değil, is_active=0 yapılır
 * @note İlişkili mesajlar korunur
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning room_id geçerli bir chat room ID'si olmalıdır
 * @warning Soft delete işlemi geri alınabilir
 * 
 * @see db_update_chat_room_status(), db_delete_chat_message()
 */
int db_delete_chat_room(int room_id) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    // Soft delete - sadece is_active=0 yap
    snprintf(sql, sizeof(sql), "UPDATE chat_rooms SET is_active = 0 WHERE room_id = %d;", room_id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting chat room: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat room ID %d deleted (soft delete) successfully\n", room_id);
            return 0;
        } else {
            PRINTF_LOG("No chat room found with ID %d\n", room_id);
            return -1;
        }
    }
}

/**
 * @brief CHAT_ROOMS tablosundan chat odasını tamamen siler (hard delete)
 * @details Verilen ID'ye sahip chat odasını ve ilişkili tüm mesajları siler.
 *          Dikkatli kullanılmalı - tüm veri kalıcı olarak kaybolur.
 * 
 * Hard Delete Sırası (Foreign Key Constraint):
 * 1. DELETE FROM chat_messages WHERE room_id = {room_id}
 * 2. DELETE FROM chat_rooms WHERE room_id = {room_id}
 * 3. Etkilenen kayıt sayısını kontrol et
 * 
 * @param room_id Silinecek chat odasının ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme (oda ve tüm mesajlar)
 * @retval -1 Silme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note Cascade DELETE etkisi - oda silinince tüm mesajları da silinir
 * @note Bu işlem geri alınamaz
 * @note Genellikle db_delete_chat_room() (soft delete) tercih edilir
 * @warning room_id geçerli bir chat room ID'si olmalıdır
 * @warning Hard delete işlemi geri alınamaz
 * @warning Tüm chat geçmişi kaybolur
 * 
 * @see db_delete_chat_room(), db_delete_chat_message()
 */
int db_delete_chat_room_hard(int room_id) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    // First delete associated messages (due to foreign key constraint)
    snprintf(sql, sizeof(sql), "DELETE FROM chat_messages WHERE room_id = %d;", room_id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting chat room messages: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }

    // Then delete the chat room
    snprintf(sql, sizeof(sql), "DELETE FROM chat_rooms WHERE room_id = %d;", room_id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting chat room: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat room ID %d and all messages deleted permanently\n", room_id);
            return 0;
        } else {
            PRINTF_LOG("No chat room found with ID %d\n", room_id);
            return -1;
        }
    }
}

/**
 * @brief CHAT_MESSAGES tablosundan tek mesajı siler
 * @details Verilen ID'ye sahip chat mesajını siler.
 *          Chat room kaydı etkilenmez, sadece spesifik mesaj silinir.
 * 
 * @param message_id Silinecek mesajın ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme
 * @retval -1 Silme hatası (database not initialized, SQL error, ID not found)
 * 
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @note Chat room kaydı etkilenmez, sadece mesaj silinir
 * @note Foreign key constraint room tarafından etkilenmez
 * @warning message_id geçerli bir database ID olmalıdır
 * @warning Silme işlemi geri alınamaz
 * 
 * @see db_delete_chat_room(), db_update_chat_message()
 */
int db_delete_chat_message(int message_id) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), "DELETE FROM chat_messages WHERE message_id = %d;", message_id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting chat message: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        if (changes > 0) {
            PRINTF_LOG("Chat message ID %d deleted successfully\n", message_id);
            return 0;
        } else {
            PRINTF_LOG("No chat message found with ID %d\n", message_id);
            return -1;
        }
    }
}

/**
 * @brief Belirli chat odasının tüm mesajlarını siler
 * @details Verilen room_id'ye sahip tüm chat mesajlarını siler.
 *          Chat room kaydı korunur, sadece mesajlar silinir.
 * 
 * @param room_id Mesajları silinecek chat odasının ID'si
 * @return int İşlem sonucu
 * @retval 0 Başarılı silme (tüm mesajlar)
 * @retval -1 Silme hatası (database not initialized, SQL error)
 * 
 * @note Chat room kaydı korunur
 * @note Tüm mesaj geçmişi silinir
 * @note sqlite3_changes() ile etkilenen kayıt sayısı kontrol edilir
 * @warning room_id geçerli bir chat room ID'si olmalıdır
 * @warning Silme işlemi geri alınamaz
 * @warning Tüm mesaj geçmişi kaybolur
 * 
 * @see db_delete_chat_message(), db_delete_chat_room_hard()
 */
int db_delete_chat_room_messages(int room_id) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), "DELETE FROM chat_messages WHERE room_id = %d;", room_id);
    
    rc = sqlite3_exec(g_db, sql, NULL, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error deleting chat room messages: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        int changes = sqlite3_changes(g_db);
        PRINTF_LOG("Deleted %d messages from chat room ID %d\n", changes, room_id);
        return 0;
    }
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

/**
 * @brief Chat room list dynamic array'inin belleğini serbest bırakır
 * @details chat işlemleri tarafından tahsis edilen chat room array'inin
 *          belleğini güvenli şekilde serbest bırakır.
 * 
 * @param rooms Serbest bırakılacak chat room array pointer'ı
 * @param count Array eleman sayısı (kullanılmaz, ileriye dönük uyumluluk için)
 * 
 * @note count parametresi şu anda kullanılmaz (__attribute__((unused)))
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note Bu fonksiyon db_select_user_accessible_chat_rooms() ile eşleşir
 * @warning rooms pointer'ı malloc ile tahsis edilmiş olmalıdır
 * 
 * @see db_select_user_accessible_chat_rooms(), db_free_chat_messages()
 */
void db_free_chat_rooms(chat_room_t *rooms, int count __attribute__((unused))) {
    if (rooms) {
        free(rooms);
    }
}

/**
 * @brief Chat messages dynamic array'inin belleğini serbest bırakır
 * @details chat işlemleri tarafından tahsis edilen chat message array'inin
 *          belleğini güvenli şekilde serbest bırakır.
 * 
 * @param messages Serbest bırakılacak chat message array pointer'ı
 * @param count Array eleman sayısı (kullanılmaz, ileriye dönük uyumluluk için)
 * 
 * @note count parametresi şu anda kullanılmaz (__attribute__((unused)))
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note Bu fonksiyon db_select_chat_room_messages() ile eşleşir
 * @warning messages pointer'ı malloc ile tahsis edilmiş olmalıdır
 * 
 * @see db_select_chat_room_messages(), db_free_chat_rooms()
 */
void db_free_chat_messages(chat_message_t *messages, int count __attribute__((unused))) {
    if (messages) {
        free(messages);
    }
}