#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "database.h"

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
    
    // Test raporları oluştur
    long current_time = time(NULL);
    
    report_t reports[] = {
        {0, -1, "Test-Durum-1", 40.0000, 30.0000, "Test raporu 1", current_time - 1000, ""},
        {0, -1, "Test-Durum-2", 40.0001, 30.0001, "Test raporu 2", current_time - 500, ""},
    };
    
    int reports_inserted = 0;
    
    // Raporları ekle
    for (int i = 0; i < 2; i++) {
        if (unit_ids[i] > 0) {
            reports[i].unit_id = unit_ids[i];
            int report_id = db_insert_report(&reports[i]);
            if (report_id > 0) {
                reports_inserted++;
                printf("  ✓ Test rapor eklendi: %s (ID: %d)\n", reports[i].status, report_id);
            }
        }
    }
    
    printf("Test veri ekleme tamamlandı: %d birim, %d rapor\n", units_inserted, reports_inserted);
    return (units_inserted > 0 && reports_inserted > 0) ? 0 : -1;
}

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
