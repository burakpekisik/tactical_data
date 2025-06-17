#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"

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
            printf("  %d. Birim ID %d - %s (%.4f, %.4f) - %ld\n", 
                   i+1, reports[i].unit_id, reports[i].status,
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

void test_reports_by_unit(void) {
    printf("\n=== Birime Göre Rapor Listeleme Test ===\n");
    
    for (int unit_id = 1; unit_id <= 4; unit_id++) {
        report_t *reports;
        int report_count;
        
        if (db_select_reports_by_unit(unit_id, &reports, &report_count) == 0) {
            printf("Birim ID %d için %d rapor bulundu:\n", unit_id, report_count);
            for (int i = 0; i < report_count; i++) {
                printf("  - %s: %s\n", reports[i].status, 
                       strlen(reports[i].description) > 0 ? reports[i].description : "Açıklama yok");
            }
            free(reports);
        }
    }
}

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
    test_reports_by_unit();
    
    printf("\n=== Testler tamamlandı ===\n");
    db_close();
    return 0;
}
