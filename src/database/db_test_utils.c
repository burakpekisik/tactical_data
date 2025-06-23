/**
 * @file db_test_utils.c
 * @brief Veritabanı test verisi oluşturma yardımcı fonksiyonları
 * @details Bu dosya test ve demo amaçlı örnek verilerin veritabanına eklenmesi
 *          işlemlerini içerir. Tactical Data Transfer System'in test data
 *          katmanını oluşturur. Gerçek askeri birim isimleri ve koordinatlar kullanır.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 * @ingroup database
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "../include/database.h"
#include "logger.h"

/**
 * @brief Veritabanına örnek test verilerini ekler
 * @details Tactical data transfer sistemi için örnek unit ve report verilerini
 *          veritabanına ekler. Test ve demo amaçlı kullanılır.
 * 
 * Eklenen Test Verileri:
 * 
 * **Test Birimleri (4 adet):**
 * - BIRIM-01: 1. Piyade Alayı (Ankara-Etimesgut)
 * - BIRIM-02: 2. Zırhlı Tuğay (Ankara-Polatlı)  
 * - BIRIM-03: Hava Savunma Taburu (İstanbul-Çatalca)
 * - BIRIM-04: Özel Kuvvetler Timi (İzmir-Foça)
 * 
 * **Test Raporları (6 adet):**
 * - Her birim için gerçekçi tactical raporlar
 * - Farklı durum kodları (Tehlike, Güvenli, Devriye, vb.)
 * - Gerçek GPS koordinatları
 * - Zaman damgalı raporlar (son 1 saat içi)
 * 
 * Koordinat Verileri:
 * - Ankara bölgesi: ~39.92°N, 32.85°E
 * - İstanbul bölgesi: ~41.00°N, 28.97°E  
 * - İzmir bölgesi: ~38.42°N, 27.14°E
 * 
 * @return int İşlem sonucu
 * @retval 0 Başarılı test verisi ekleme (en az 1 unit ve 1 report)
 * @retval -1 Test verisi ekleme hatası veya hiç veri eklenemedi
 * 
 * @note Bu fonksiyon demo ve test amaçlıdır, production'da kullanılmamalı
 * @note Gerçek askeri lokasyonlar ve birim isimleri kullanır
 * @note Timestamp değerleri çağrı anından geriye doğru hesaplanır
 * @note Her unit için unit_id foreign key automatic assignment yapılır
 * @warning Mevcut veriler üzerine ekleme yapar, duplicate check yok
 * 
 * @see db_insert_unit(), db_insert_report(), unit_t, report_t
 * 
 * @example
 * @code
 * // Test verilerini ekle
 * if (db_insert_test_data() == 0) {
 *     printf("Test verileri başarıyla eklendi\n");
 * }
 * @endcode
 */
int db_insert_test_data(void) {
    printf("Test verileri ekleniyor...\n");
    fflush(stdout);
    
    // Test birimleri oluştur
    unit_t units[] = {
        {0, "BIRIM-01", "1. Piyade Alayi", "Piyade", "Ankara - Etimesgut", 1, ""},
        {0, "BIRIM-02", "2. Zirhli Tugay", "Zirhli", "Ankara - Polatli", 1, ""},
        {0, "BIRIM-03", "Hava Savunma Taburu", "Hava Savunma", "Istanbul - Catalca", 1, ""},
        {0, "BIRIM-04", "Ozel Kuvvetler Timi", "Ozel Kuvvet", "Izmir - Foca", 1, ""}
    };
    
    int unit_ids[4];
    int units_inserted = 0;
    
    // Birimleri ekle
    for (int i = 0; i < 4; i++) {
        int unit_id = db_insert_unit(&units[i]);
        if (unit_id > 0) {
            unit_ids[i] = unit_id;
            units_inserted++;
            printf("  ✓ %s eklendi (ID: %d)\n", units[i].unit_id, unit_id);
            fflush(stdout);
        } else {
            printf("  ✗ %s eklenemedi\n", units[i].unit_id);
            fflush(stdout);
            unit_ids[i] = -1;
        }
    }
    
    // Test kullanıcıları oluştur
    // (Her birim için bir kullanıcı, salt ve hash örnekleriyle)
    char default_salt[17] = "testsalt12345678";
    char default_hash[129] = "$argon2id$v=19$m=65536,t=3,p=1$testsalt12345678$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhash";
    struct {
        int unit_id;
        char username[32];
        char name[32];
        char surname[32];
        char password[129];
        char salt[17];
        int privilege;
    } users[] = {
        {0, "", "", "", "", "", 1},
        {0, "", "", "", "", "", 1},
        {0, "", "", "", "", "", 1},
        {0, "", "", "", "", "", 1}
    };
    // Bilgileri strcpy ile ata
    strcpy(users[0].username, "birim01user");
    strcpy(users[0].name, "Ali");
    strcpy(users[0].surname, "Yılmaz");
    strcpy(users[0].password, default_hash);
    strcpy(users[0].salt, default_salt);
    
    strcpy(users[1].username, "birim02user");
    strcpy(users[1].name, "Veli");
    strcpy(users[1].surname, "Demir");
    strcpy(users[1].password, default_hash);
    strcpy(users[1].salt, default_salt);
    
    strcpy(users[2].username, "birim03user");
    strcpy(users[2].name, "Ayşe");
    strcpy(users[2].surname, "Kaya");
    strcpy(users[2].password, default_hash);
    strcpy(users[2].salt, default_salt);
    
    strcpy(users[3].username, "birim04user");
    strcpy(users[3].name, "Fatma");
    strcpy(users[3].surname, "Çelik");
    strcpy(users[3].password, default_hash);
    strcpy(users[3].salt, default_salt);
    
    int user_ids[4];
    int users_inserted = 0;
    for (int i = 0; i < 4; i++) {
        users[i].unit_id = unit_ids[i];
        int user_id = db_insert_user(users[i].unit_id, users[i].username, users[i].name, users[i].surname, users[i].password, users[i].salt, users[i].privilege);
        if (user_id > 0) {
            user_ids[i] = user_id;
            users_inserted++;
            printf("  ✓ Kullanıcı eklendi: %s (ID: %d)\n", users[i].username, user_id);
            fflush(stdout);
        } else {
            printf("  ✗ Kullanıcı eklenemedi: %s\n", users[i].username);
            fflush(stdout);
            user_ids[i] = -1;
        }
    }
    
    // Test raporları oluştur
    long current_time = time(NULL);
    
    report_t reports[] = {
        // BIRIM-01 raporları
        {0, -1, "Tehlike", 39.9208, 32.8541, 
         "Dusman temasi tespit edildi. Acil mudahale gerekli.", 
         current_time - 3600, ""},
        {0, -1, "Guvenli", 39.9250, 32.8580, 
         "Tehdit bertaraf edildi. Pozisyon guvenli hale getirildi.", 
         current_time - 1800, ""},
        
        // BIRIM-02 raporları  
        {0, -1, "Devriye", 39.9180, 32.8600, 
         "Rutin devriye gorevi devam ediyor. Anormallik yok.", 
         current_time - 2400, ""},
        {0, -1, "Konuslanma", 39.9200, 32.8620, 
         "Stratejik noktada konuslanma tamamlandi. Bolge guvenli.", 
         current_time - 900, ""},
        
        // BIRIM-03 raporları
        {0, -1, "Hazir", 41.0082, 28.9784, 
         "Hava savunma sistemleri aktif. Radar taramasi devam ediyor.", 
         current_time - 1200, ""},
        
        // BIRIM-04 raporları
        {0, -1, "Gorev", 38.4237, 27.1428, 
         "Ozel operasyon baslatildi. Sessizlik protokolu uygulanıyor.", 
         current_time - 600, ""}
    };
    
    int reports_inserted = 0;
    
    // Raporları ekle
    for (int i = 0; i < 6; i++) {
        int user_index;
        if (i < 2) user_index = 0;      // BIRIM-01
        else if (i < 4) user_index = 1; // BIRIM-02  
        else if (i < 5) user_index = 2; // BIRIM-03
        else user_index = 3;            // BIRIM-04
        if (user_ids[user_index] > 0) {
            reports[i].user_id = user_ids[user_index];
            int report_id = db_insert_report(&reports[i]);
            if (report_id > 0) {
                reports_inserted++;
                printf("  ✓ Rapor eklendi: %s - %s (ID: %d)\n", 
                       users[user_index].username, reports[i].status, report_id);
                fflush(stdout);
            } else {
                printf("  ✗ Rapor eklenemedi: %s - %s\n", 
                       users[user_index].username, reports[i].status);
                fflush(stdout);
            }
        }
    }
    printf("Test verileri ekleme tamamlandi:\n");
    printf("  - %d birim eklendi\n", units_inserted);
    printf("  - %d kullanıcı eklendi\n", users_inserted);
    printf("  - %d rapor eklendi\n", reports_inserted);
    fflush(stdout);
    return (units_inserted > 0 && users_inserted > 0 && reports_inserted > 0) ? 0 : -1;
}
