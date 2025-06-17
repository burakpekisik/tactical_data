#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "../include/database.h"

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
        int unit_index;
        if (i < 2) unit_index = 0;      // BIRIM-01
        else if (i < 4) unit_index = 1; // BIRIM-02  
        else if (i < 5) unit_index = 2; // BIRIM-03
        else unit_index = 3;            // BIRIM-04
        
        if (unit_ids[unit_index] > 0) {
            reports[i].unit_id = unit_ids[unit_index];
            int report_id = db_insert_report(&reports[i]);
            if (report_id > 0) {
                reports_inserted++;
                printf("  ✓ Rapor eklendi: %s - %s (ID: %d)\n", 
                       units[unit_index].unit_id, reports[i].status, report_id);
                fflush(stdout);
            } else {
                printf("  ✗ Rapor eklenemedi: %s - %s\n", 
                       units[unit_index].unit_id, reports[i].status);
                fflush(stdout);
            }
        }
    }
    
    printf("Test verileri ekleme tamamlandi:\n");
    printf("  - %d birim eklendi\n", units_inserted);
    printf("  - %d rapor eklendi\n", reports_inserted);
    fflush(stdout);
    
    return (units_inserted > 0 && reports_inserted > 0) ? 0 : -1;
}
