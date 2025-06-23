/**
 * @file test_data_standalone.c
 * @brief Bağımsız veritabanı test verisi oluşturucu - minimal test senaryoları için
 * @ingroup database_tests
 * @author Taktik Veri Sistemi
 * @date 2025
 * 
 * Bu dosya minimal test verisi oluşturan bağımsız bir test aracı sağlar.
 * Ana uygulama altyapısına ihtiyaç duymadan bağımsız olarak çalıştırılabilir.
 * 
 * 
 * Kullanım:
 * @code
 * ./test_data_standalone [veritabani_yolu]
 * @endcode
 * 
 * @note Bu araç birim testleri ve CI/CD pipeline'ları için tasarlanmıştır.
 *       Temel işlevsellik doğrulaması için minimal test verisi yeterlidir.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "database.h"

/**
 * @brief Bağımsız test için minimal test verisini veritabanına ekler
 * @ingroup database_tests
 * 
 * Bu fonksiyon şu temel test verisini oluşturur ve ekler:
 * - 2 test askeri birimi (TEST-01, TEST-02)
 * - 2 karşılık gelen zaman damgalı taktik rapor
 * 
 * Fonksiyon şu işlemleri gerçekleştirir:
 * 1. Temel bilgilerle test birim yapıları oluşturur
 * 2. Birimleri veritabanına ekler ve ID'lerini yakalar
 * 3. Eklenen birimlerle bağlantılı test raporları oluşturur
 * 4. Raporları mevcut zaman damgası varyasyonlarıyla ekler
 * 5. Doğrulama için detaylı konsol çıktısı sağlar
 * 
 * @return Başarıda 0 (en az bir birim ve rapor eklendi)
 * @return Başarısızlıkta -1 (hiçbir veri başarıyla eklenmedi)
 * 
 * @note Bu fonksiyon şunlar için uygun basit test verisi üretir:
 *       - Veritabanı işlemlerinin birim testleri
 *       - CI/CD pipeline doğrulaması
 *       - Hızlı geliştirme testleri
 * 
 * @warning Fonksiyon veritabanının zaten başlatıldığını ve tabloların mevcut olduğunu varsayar
 * 
 * @see db_insert_unit()
 * @see db_insert_report()
 * 
 * Örnek çıktı:
 * @code
 * === Standalone Test Veri Ekleme ===
 *   ✓ TEST-01 eklendi (ID: 1)
 *   ✓ TEST-02 eklendi (ID: 2)
 *   ✓ Test rapor eklendi: Test-Durum-1 (ID: 1)
 *   ✓ Test rapor eklendi: Test-Durum-2 (ID: 2)
 * Test veri ekleme tamamlandı: 2 birim, 2 rapor
 * @endcode
 */
// Test data ekleme fonksiyonu (standalone test için)
int insert_test_data_standalone(void) {
    printf("=== Standalone Test Veri Ekleme ===\n");
    
    // Test birimleri oluştur
    unit_t units[] = {
        {0, "TEST-01", "Test Birlik 1", "Test", "Test Lokasyon 1", 1, ""},
        {0, "TEST-02", "Test Birlik 2", "Test", "Test Lokasyon 2", 1, ""},
    };
    
    int unit_ids[2];
    int units_inserted = 0;
    
    // Birimleri ekle
    for (int i = 0; i < 2; i++) {
        int unit_id = db_insert_unit(&units[i]);
        if (unit_id > 0) {
            unit_ids[i] = unit_id;
            units_inserted++;
            printf("  ✓ %s eklendi (ID: %d)\n", units[i].unit_id, unit_id);
        } else {
            printf("  ✗ %s eklenemedi\n", units[i].unit_id);
            unit_ids[i] = -1;
        }
    }
    
    // Test kullanıcıları oluştur
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
        {0, "test01user", "Test1", "Kullanici", "", "", 1},
        {0, "test02user", "Test2", "Kullanici", "", "", 1}
    };
    // String alanları strcpy ile ata
    strcpy(users[0].password, default_hash);
    strcpy(users[0].salt, default_salt);
    strcpy(users[1].password, default_hash);
    strcpy(users[1].salt, default_salt);
    int user_ids[2];
    int users_inserted = 0;
    for (int i = 0; i < 2; i++) {
        users[i].unit_id = unit_ids[i];
        int user_id = db_insert_user(users[i].unit_id, users[i].username, users[i].name, users[i].surname, users[i].password, users[i].salt, users[i].privilege);
        if (user_id > 0) {
            user_ids[i] = user_id;
            users_inserted++;
            printf("  ✓ Kullanıcı eklendi: %s (ID: %d)\n", users[i].username, user_id);
        } else {
            printf("  ✗ Kullanıcı eklenemedi: %s\n", users[i].username);
            user_ids[i] = -1;
        }
    }
    // Test raporları oluştur
    long current_time = time(NULL);
    report_t reports[] = {
        {0, -1, "Test-Durum-1", 40.0000, 30.0000, "Test raporu 1", current_time - 1000, ""},
        {0, -1, "Test-Durum-2", 40.0001, 30.0001, "Test raporu 2", current_time - 500, ""},
    };
    int reports_inserted = 0;
    // Raporları ekle (her rapor ilgili kullanıcının user_id'si ile)
    for (int i = 0; i < 2; i++) {
        if (user_ids[i] > 0) {
            reports[i].user_id = user_ids[i];
            int report_id = db_insert_report(&reports[i]);
            if (report_id > 0) {
                reports_inserted++;
                printf("  ✓ Test rapor eklendi: %s (ID: %d)\n", reports[i].status, report_id);
            }
        }
    }
    printf("Test veri ekleme tamamlandı: %d birim, %d kullanıcı, %d rapor\n", units_inserted, users_inserted, reports_inserted);
    return (units_inserted > 0 && users_inserted > 0 && reports_inserted > 0) ? 0 : -1;
}

/**
 * @brief Bağımsız veritabanı test verisi oluşturucu ana fonksiyonu
 * @ingroup database_tests
 * 
 * Bu bağımsız test verisi oluşturucu için giriş noktasıdır. Tam bir
 * veritabanı kurulumu ve test verisi ekleme döngüsü gerçekleştirir:
 * 
 * 1. Veritabanı bağlantısını başlatır
 * 2. Gerekli tabloları oluşturur
 * 3. Test verisini ekler
 * 4. Başarı/başarısızlık geri bildirimi sağlar
 * 5. Veritabanı bağlantısını düzgün şekilde kapatır
 * 
 * @param argc Argüman sayısı
 * @param argv Argüman vektörü
 *             - argv[1]: Opsiyonel veritabanı yolu (varsayılan: "test_tactical_data.db")
 * 
 * @return Başarıda 0
 * @return Veritabanı başlatma hatalarında 1
 * @return Tablo oluşturma hatalarında 1
 * @return Test verisi ekleme hatalarında 1
 * 
 * @note Bu fonksiyon tam uygulama gerektirmeden hızlı test senaryoları için
 *       bağımsız bir çalıştırılabilir dosya olarak tasarlanmıştır.
 * 
 * @warning Başarısızlık durumunda bile dönmeden önce her zaman veritabanı bağlantısını kapatır
 * 
 * Kullanım örnekleri:
 * @code
 * // Varsayılan veritabanı yolunu kullan
 * ./test_data_standalone
 * 
 * // Özel veritabanı yolu belirt
 * ./test_data_standalone /path/to/custom.db
 * 
 * // CI/CD pipeline'da
 * ./test_data_standalone test_db.db && echo "Test verisi hazır"
 * @endcode
 * 
 * @see db_init()
 * @see db_create_tables()
 * @see insert_test_data_standalone()
 * @see db_close()
 */
// Standalone test için main fonksiyonu
int main(int argc, char* argv[]) {
    const char *db_path = (argc > 1) ? argv[1] : "test_tactical_data.db";
    
    printf("=== Database Test Veri Ekleme ===\n");
    
    if (db_init(db_path) != 0) {
        printf("Database bağlantısı başarısız!\n");
        return 1;
    }
    
    if (db_create_tables() != 0) {
        printf("Tablolar oluşturulamadı!\n");
        db_close();
        return 1;
    }
    
    if (insert_test_data_standalone() != 0) {
        printf("Test verileri eklenemedi!\n");
        db_close();
        return 1;
    }
    
    printf("\n=== Test başarıyla tamamlandı ===\n");
    db_close();
    return 0;
}
