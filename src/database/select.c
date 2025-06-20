/**
 * @file select.c
 * @brief Veritabanı sorgulama ve veri çekme işlemleri
 * @details Bu dosya SQLite3 veritabanından unit ve report verilerinin sorgulanması,
 *          filtrelenmesi ve callback fonksiyonları ile veri toplanması işlemlerini
 *          içerir. Tactical Data Transfer System'in veri okuma katmanını oluşturur.
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
#include "logger.h"

/**
 * @brief External global veritabanı bağlantısı
 * @details create.c'de tanımlanan global veritabanı bağlantısına referans
 * @see g_db in create.c
 */
extern sqlite3 *g_db;

/**
 * @brief UNITS tablosu callback fonksiyonu
 * @details sqlite3_exec() tarafından çağrılan callback. Her unit record'u için
 *          çağrılır ve dynamic array'e unit verilerini ekler.
 * 
 * Callback Data Formatı:
 * - data[0]: unit_t** (units array pointer)
 * - data[1]: int* (current count)
 * - data[2]: int* (array capacity)
 * 
 * @param data Callback veri paketi (unit array, count, capacity)
 * @param argc Column sayısı
 * @param argv Column değerleri array'i
 * @param azColName Column isimleri array'i
 * @return int Callback sonucu (0: devam, non-zero: abort)
 * 
 * @note Dynamic memory reallocation yapabilir
 * @note NULL değerler güvenli şekilde handle edilir
 * @warning Buffer overflow koruması için strncpy kullanılır
 * 
 * @see db_select_all_units(), unit_t
 */
static int unit_callback(void *data, int argc, char **argv, char **azColName) {
    unit_t **units = (unit_t **)((void**)data)[0];
    int *count = (int *)((void**)data)[1];
    int *capacity = (int *)((void**)data)[2];

    if (*count >= *capacity) {
        *capacity *= 2;
        *units = realloc(*units, *capacity * sizeof(unit_t));
    }

    unit_t *unit = &(*units)[*count];
    memset(unit, 0, sizeof(unit_t));

    for(int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "ID") == 0 && argv[i]) {
            unit->id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "UNIT_ID") == 0 && argv[i]) {
            strncpy(unit->unit_id, argv[i], sizeof(unit->unit_id) - 1);
        } else if (strcmp(azColName[i], "UNIT_NAME") == 0 && argv[i]) {
            strncpy(unit->unit_name, argv[i], sizeof(unit->unit_name) - 1);
        } else if (strcmp(azColName[i], "UNIT_TYPE") == 0 && argv[i]) {
            strncpy(unit->unit_type, argv[i], sizeof(unit->unit_type) - 1);
        } else if (strcmp(azColName[i], "LOCATION") == 0 && argv[i]) {
            strncpy(unit->location, argv[i], sizeof(unit->location) - 1);
        } else if (strcmp(azColName[i], "ACTIVE") == 0 && argv[i]) {
            unit->active = atoi(argv[i]);
        } else if (strcmp(azColName[i], "CREATED_AT") == 0 && argv[i]) {
            strncpy(unit->created_at, argv[i], sizeof(unit->created_at) - 1);
        }
    }
    (*count)++;
    return 0;
}

/**
 * @brief REPORTS tablosu callback fonksiyonu
 * @details sqlite3_exec() tarafından çağrılan callback. Her report record'u için
 *          çağrılır ve dynamic array'e report verilerini ekler.
 * 
 * Callback Data Formatı:
 * - data[0]: report_t** (reports array pointer)
 * - data[1]: int* (current count)
 * - data[2]: int* (array capacity)
 * 
 * @param data Callback veri paketi (report array, count, capacity)
 * @param argc Column sayısı
 * @param argv Column değerleri array'i
 * @param azColName Column isimleri array'i
 * @return int Callback sonucu (0: devam, non-zero: abort)
 * 
 * @note Koordinatlar atof() ile double'a çevrilir
 * @note Timestamp atol() ile long'a çevrilir
 * @note Dynamic memory reallocation yapabilir
 * @warning Buffer overflow koruması için strncpy kullanılır
 * 
 * @see db_select_all_reports(), report_t
 */
static int report_callback(void *data, int argc, char **argv, char **azColName) {
    report_t **reports = (report_t **)((void**)data)[0];
    int *count = (int *)((void**)data)[1];
    int *capacity = (int *)((void**)data)[2];

    if (*count >= *capacity) {
        *capacity *= 2;
        *reports = realloc(*reports, *capacity * sizeof(report_t));
    }

    report_t *report = &(*reports)[*count];
    memset(report, 0, sizeof(report_t));

    for(int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "ID") == 0 && argv[i]) {
            report->id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "UNIT_ID") == 0 && argv[i]) {
            report->unit_id = atoi(argv[i]);
        } else if (strcmp(azColName[i], "STATUS") == 0 && argv[i]) {
            strncpy(report->status, argv[i], sizeof(report->status) - 1);
        } else if (strcmp(azColName[i], "LATITUDE") == 0 && argv[i]) {
            report->latitude = atof(argv[i]);
        } else if (strcmp(azColName[i], "LONGITUDE") == 0 && argv[i]) {
            report->longitude = atof(argv[i]);
        } else if (strcmp(azColName[i], "DESCRIPTION") == 0 && argv[i]) {
            strncpy(report->description, argv[i], sizeof(report->description) - 1);
        } else if (strcmp(azColName[i], "TIMESTAMP") == 0 && argv[i]) {
            report->timestamp = atol(argv[i]);
        } else if (strcmp(azColName[i], "CREATED_AT") == 0 && argv[i]) {
            strncpy(report->created_at, argv[i], sizeof(report->created_at) - 1);
        }
    }
    (*count)++;
    return 0;
}

/**
 * @brief Tüm unit kayıtlarını sorgular
 * @details UNITS tablosundaki tüm kayıtları CREATED_AT'e göre ters sıralı (en yeni önce)
 *          olarak getirir. Dynamic array allocation kullanır.
 * 
 * Sorgu Özellikleri:
 * - ORDER BY CREATED_AT DESC (en yeni kayıtlar önce)
 * - Dynamic memory allocation (başlangıç 10, gerektiğinde 2x artış)
 * - Callback-based result processing
 * 
 * @param units [OUT] Unit array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen unit sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama
 * @retval -1 Sorgu hatası (database not initialized, SQL error)
 * 
 * @note units array'i çağıran tarafından free() edilmelidir
 * @note count 0 ise units NULL olabilir
 * @warning units ve count pointer'ları NULL olmamalıdır
 * 
 * @see unit_callback(), unit_t, db_select_reports()
 */
int db_select_units(unit_t **units, int *count) {
    char *zErrMsg = 0;
    int rc;
    char *sql = "SELECT * FROM UNITS ORDER BY CREATED_AT DESC";

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    *count = 0;
    int capacity = 10;
    *units = malloc(capacity * sizeof(unit_t));

    void *callback_data[] = {units, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, unit_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting units: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*units);
        return -1;
    }

    return 0;
}

/**
 * @brief Tüm report kayıtlarını sorgular
 * @details REPORTS tablosundaki tüm kayıtları TIMESTAMP'e göre ters sıralı (en yeni önce)
 *          olarak getirir. Dynamic array allocation kullanır.
 * 
 * Sorgu Özellikleri:
 * - ORDER BY TIMESTAMP DESC (en yeni raporlar önce)
 * - Dynamic memory allocation (başlangıç 10, gerektiğinde 2x artış)
 * - Callback-based result processing
 * - Tüm report alanları dahil (koordinatlar, durum, açıklama)
 * 
 * @param reports [OUT] Report array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen report sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama
 * @retval -1 Sorgu hatası (database not initialized, SQL error)
 * 
 * @note reports array'i çağıran tarafından free() edilmelidir
 * @note Koordinatlar double precision ile döner
 * @warning reports ve count pointer'ları NULL olmamalıdır
 * 
 * @see report_callback(), report_t, db_select_reports_by_unit()
 */
int db_select_reports(report_t **reports, int *count) {
    char *zErrMsg = 0;
    int rc;
    char *sql = "SELECT * FROM REPORTS ORDER BY TIMESTAMP DESC";

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    *count = 0;
    int capacity = 10;
    *reports = malloc(capacity * sizeof(report_t));

    void *callback_data[] = {reports, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, report_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting reports: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*reports);
        return -1;
    }

    return 0;
}

/**
 * @brief Belirli bir unit'e ait report kayıtlarını sorgular
 * @details Verilen unit_id'ye sahip tüm raporları TIMESTAMP'e göre ters sıralı
 *          (en yeni önce) olarak getirir. Unit-specific filtering yapar.
 * 
 * Sorgu Özellikleri:
 * - WHERE UNIT_ID = {unit_id} filter
 * - ORDER BY TIMESTAMP DESC (en yeni raporlar önce)
 * - Dynamic memory allocation
 * - Foreign key relationship ile UNITS tablosuna bağlı
 * 
 * @param unit_id Filtrelenecek unit'in database ID'si
 * @param reports [OUT] Report array pointer'ı (malloc ile tahsis edilir)
 * @param count [OUT] Dönen report sayısı
 * @return int İşlem sonucu
 * @retval 0 Başarılı sorgulama (0 sonuç da başarılıdır)
 * @retval -1 Sorgu hatası (database not initialized, SQL error)
 * 
 * @note reports array'i çağıran tarafından free() edilmelidir
 * @note unit_id foreign key constraint ile validate edilir
 * @note count 0 ise unit'e ait report yok demektir
 * @warning reports ve count pointer'ları NULL olmamalıdır
 * @warning unit_id geçerli bir UNITS.ID olmalıdır
 * 
 * @see report_callback(), report_t, db_select_reports()
 */
int db_select_reports_by_unit(int unit_id, report_t **reports, int *count) {
    char *zErrMsg = 0;
    char sql[256];
    int rc;

    if (!g_db) {
        fprintf(stderr, "Database not initialized\n");
        return -1;
    }

    snprintf(sql, sizeof(sql), 
        "SELECT * FROM REPORTS WHERE UNIT_ID = %d ORDER BY TIMESTAMP DESC", unit_id);

    *count = 0;
    int capacity = 10;
    *reports = malloc(capacity * sizeof(report_t));

    void *callback_data[] = {reports, count, &capacity};
    
    rc = sqlite3_exec(g_db, sql, report_callback, callback_data, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error selecting reports by unit: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(*reports);
        return -1;
    }

    return 0;
}