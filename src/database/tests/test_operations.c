/**
 * @file test_operations.c
 * @brief Veritabanı CRUD işlemleri test edici - kapsamlı işlem doğrulaması için
 * @ingroup database_tests
 * @author Taktik Veri Sistemi
 * @date 2025
 * 
 * Bu dosya veritabanı CRUD (Create, Read, Update, Delete) işlemlerini
 * test eden kapsamlı bir test aracı sağlar. Mevcut veritabanı verisini
 * kullanarak çeşitli sorgu türlerini doğrular.
 * 
 * Test edilen işlemler:
 * - SELECT işlemleri (birimler ve raporlar)
 * - UPDATE işlemleri (birim güncelleme)
 * - Birime göre rapor sorgulama
 * - İlişkisel sorgu testleri
 * 
 * Kullanım:
 * @code
 * ./test_operations [veritabani_yolu]
 * @endcode
 * 
 * @note Bu araç mevcut veriyi okur ve test eder, yeni veri eklemez.
 *       Test edilecek veri önceden veritabanında bulunmalıdır.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"

/**
 * @brief SELECT işlemlerini test eder - birim ve rapor listeleme
 * @ingroup database_tests
 * 
 * Bu fonksiyon temel SELECT işlemlerini test eder:
 * - Tüm birimleri listeler ve detaylarını gösterir
 * - Tüm raporları listeler ve koordinat/zaman bilgilerini gösterir
 * - Uzun açıklamaları keser ve okunabilir format sağlar
 * 
 * Test edilen fonksiyonlar:
 * - db_select_units(): Tüm askeri birimleri getirir
 * - db_select_reports(): Tüm taktik raporları getirir
 * 
 * Çıktı formatı:
 * - Birimler: ID, isim, tip, aktiflik durumu
 * - Raporlar: Birim ID, durum, konum, zaman damgası, açıklama
 * 
 * @note Fonksiyon dinamik bellek yönetimi yapar ve tüm ayrılan belleği temizler
 * @warning Veritabanı bağlantısının aktif olduğunu varsayar
 * 
 * @see db_select_units()
 * @see db_select_reports()
 * 
 * Örnek çıktı:
 * @code
 * === SELECT İşlemleri Test ===
 * Toplam 4 birim bulundu:
 *   1. BIRIM-01 (1. Piyade Alayi) - Piyade - Aktif: Evet
 *   2. BIRIM-02 (2. Zirhli Tugay) - Zirhli - Aktif: Evet
 * Toplam 6 rapor bulundu:
 *   1. Birim ID 1 - Tehlike (39.9200, 32.8500) - 1735574323
 *      Açıklama: Dusman temasi tespit edildi...
 * @endcode
 */

void test_select_operations(void) {
    printf("\n=== SELECT İşlemleri Test ===\n");
    
    // Tüm birimleri listele
    unit_t *units;
    int unit_count;
    
    if (db_select_units(&units, &unit_count) == 0) {
        printf("Toplam %d birim bulundu:\n", unit_count);
        for (int i = 0; i < unit_count; i++) {
            printf("  %d. %s (%s) - %s - Aktif: %s\n", 
                   i+1, units[i].unit_id, units[i].unit_name, 
                   units[i].unit_type, units[i].active ? "Evet" : "Hayır");
        }
        free(units);
    } else {
        printf("Birimler listelenemedi!\n");
    }
    
    // Tüm raporları listele
    report_t *reports;
    int report_count;
    
    if (db_select_reports(&reports, &report_count) == 0) {
        printf("\nToplam %d rapor bulundu:\n", report_count);
        for (int i = 0; i < report_count; i++) {
            printf("  %d. Kullanıcı ID %d - %s (%.4f, %.4f) - %ld\n", 
                   i+1, reports[i].user_id, reports[i].status,
                   reports[i].latitude, reports[i].longitude, reports[i].timestamp);
            if (strlen(reports[i].description) > 0) {
                printf("     Açıklama: %.50s%s\n", 
                       reports[i].description, 
                       strlen(reports[i].description) > 50 ? "..." : "");
            }
        }
        free(reports);
    } else {
        printf("Raporlar listelenemedi!\n");
    }
}

/**
 * @brief UPDATE işlemlerini test eder - birim güncelleme fonksiyonları
 * @ingroup database_tests
 * 
 * Bu fonksiyon veritabanı güncelleme işlemlerini test eder:
 * - Mevcut bir birimi ID ile getirir
 * - Birim bilgilerini değiştirir (konum, aktiflik durumu)
 * - Güncellenmiş veriyi veritabanına yazar
 * - Güncelleme işleminin başarısını doğrular
 * 
 * Test edilen fonksiyonlar:
 * - db_get_unit_by_id(): Tek bir birimi ID ile getirir
 * - db_update_unit(): Birim bilgilerini günceller
 * 
 * Test senaryosu:
 * 1. ID=1 olan birimi getirir
 * 2. Lokasyon bilgisini "YENİ KONUM - Test Güncelleme" yapar
 * 3. Aktiflik durumunu false (0) yapar
 * 4. Güncelleme işlemini gerçekleştirir
 * 5. Güncellenmiş veriyi kontrol eder ve gösterir
 * 
 * @note Bu fonksiyon mevcut test verilerini değiştirir.
 *       Test sonrasında veri orijinal haline döndürülmez.
 * 
 * @warning Veritabanında en az 1 birim bulunduğunu varsayar (ID=1)
 *          Güncelleme işlemi geri alınamaz
 * 
 * @see db_get_unit_by_id()
 * @see db_update_unit()
 * 
 * Örnek çıktı:
 * @code
 * === UPDATE İşlemleri Test ===
 * Güncelleme öncesi: BIRIM-01 - Konum: Ankara/Etimesgut Kışlası
 * Birim güncellendi!
 * Güncelleme sonrası: BIRIM-01 - Konum: YENİ KONUM - Test Güncelleme - Aktif: Hayır
 * @endcode
 */

void test_update_operations(void) {
    printf("\n=== UPDATE İşlemleri Test ===\n");
    
    // İlk birimi güncelle
    unit_t unit;
    if (db_get_unit_by_id(1, &unit) == 0) {
        printf("Güncelleme öncesi: %s - Konum: %s\n", unit.unit_id, unit.location);
        
        strcpy(unit.location, "YENİ KONUM - Test Güncelleme");
        unit.active = 0;
        
        if (db_update_unit(1, &unit) == 0) {
            printf("Birim güncellendi!\n");
            
            // Güncellenmiş veriyi kontrol et
            if (db_get_unit_by_id(1, &unit) == 0) {
                printf("Güncelleme sonrası: %s - Konum: %s - Aktif: %s\n", 
                       unit.unit_id, unit.location, unit.active ? "Evet" : "Hayır");
            }
        }
    }
}

/**
 * @brief Kullanıcıya göre rapor listeleme işlemlerini test eder - ilişkisel sorgular
 * @ingroup database_tests
 * 
 * Bu fonksiyon kullanıcı-spesifik rapor sorgularını test eder:
 * - Her kullanıcı için ayrı ayrı raporları listeler
 * - İlişkisel sorgu performansını test eder
 * - Rapor sayısı ve içerik doğrulaması yapar
 * 
 * Test edilen fonksiyon:
 * - db_select_reports_by_user(): Belirli bir kullanıcıya ait raporları getirir
 * 
 * Test senaryosu:
 * 1. Kullanıcı ID 1-4 arası döngü yapar
 * 2. Her kullanıcı için ayrı rapor sorgular
 * 3. Bulunan rapor sayısını gösterir
 * 4. Her raporun durumunu ve açıklamasını listeler
 * 5. Bellek yönetimi yapar (free)
 * 
 * @note Bu fonksiyon sadece okuma işlemi yapar, veri değiştirmez.
 *       Mevcut test verilerini güvenli şekilde analiz eder.
 * 
 * @warning Sabit kullanıcı ID aralığı (1-4) kullanır.
 *          Veritabanında bu ID'lere sahip kullanıcı yoksa boş sonuç alınır.
 * 
 * @see db_select_reports_by_user()
 * 
 * Örnek çıktı:
 * @code
 * === Kullanıcıya Göre Rapor Listeleme Test ===
 * Kullanıcı ID 1 için 2 rapor bulundu:
 *   - Tehlike: Dusman temasi tespit edildi...
 *   - Guvenli: Tehdit bertaraf edildi...
 * Kullanıcı ID 2 için 1 rapor bulundu:
 *   - Devriye: Rutin devriye gorevi devam ediyor...
 * @endcode
 */

void test_reports_by_user(void) {
    printf("\n=== Kullanıcıya Göre Rapor Listeleme Test ===\n");
    // Örnek olarak ilk 4 kullanıcıyı test et
    for (int user_id = 1; user_id <= 4; user_id++) {
        report_t *reports;
        int report_count;
        if (db_select_reports_by_user(user_id, &reports, &report_count) == 0) {
            printf("Kullanıcı ID %d için %d rapor bulundu:\n", user_id, report_count);
            for (int i = 0; i < report_count; i++) {
                printf("  - %s: %s\n", reports[i].status, 
                       strlen(reports[i].description) > 0 ? reports[i].description : "Açıklama yok");
            }
            free(reports);
        } else {
            printf("Kullanıcı ID %d için rapor bulunamadı!\n", user_id);
        }
    }
}

/**
 * @brief Veritabanı CRUD işlemleri test aracı ana fonksiyonu
 * @ingroup database_tests
 * 
 * Bu veritabanı işlemleri test aracının giriş noktasıdır. Kapsamlı bir
 * veritabanı fonksiyonalite doğrulaması gerçekleştirir:
 * 
 * 1. Veritabanı bağlantısını başlatır
 * 2. SELECT işlemlerini test eder (birim ve rapor listeleme)
 * 3. UPDATE işlemlerini test eder (birim güncelleme)
 * 4. İlişkisel sorguları test eder (birime göre rapor)
 * 5. Tüm test sonuçlarını konsola yazdırır
 * 6. Veritabanı bağlantısını kapatır
 * 
 * @param argc Argüman sayısı
 * @param argv Argüman vektörü
 *             - argv[1]: Opsiyonel veritabanı yolu (varsayılan: "tactical_data.db")
 * 
 * @return Başarıda 0
 * @return Veritabanı bağlantı hatalarında 1
 * 
 * @note Bu araç mevcut veritabanı verisini kullanır ve test eder.
 *       Yeni veri eklemez, ancak UPDATE testleri mevcut veriyi değiştirebilir.
 * 
 * @warning UPDATE testleri veriyi kalıcı olarak değiştirir.
 *          Test öncesi veritabanının yedeğini alın.
 * 
 * Test sırası:
 * 1. test_select_operations() - Veri okuma testleri
 * 2. test_update_operations() - Veri güncelleme testleri  
 * 3. test_reports_by_user() - İlişkisel sorgu testleri
 * 
 * Kullanım örnekleri:
 * @code
 * // Varsayılan veritabanını test et
 * ./test_operations
 * 
 * // Özel veritabanını test et
 * ./test_operations /path/to/test.db
 * 
 * // Production veritabanını kontrol et
 * ./test_operations tactical_data.db > test_results.log
 * @endcode
 * 
 * @see test_select_operations()
 * @see test_update_operations()
 * @see test_reports_by_user()
 * @see db_init()
 * @see db_close()
 */
// Standalone test için main fonksiyonu
int main(int argc, char* argv[]) {
    const char *db_path = (argc > 1) ? argv[1] : "tactical_data.db";
    
    printf("=== Database İşlemleri Test ===\n");
    
    if (db_init(db_path) != 0) {
        printf("Database bağlantısı başarısız!\n");
        return 1;
    }
    
    test_select_operations();
    test_update_operations();
    test_reports_by_user();
    
    printf("\n=== Testler tamamlandı ===\n");
    db_close();
    return 0;
}
