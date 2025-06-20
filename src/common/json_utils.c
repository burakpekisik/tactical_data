/**
 * @file json_utils.c
 * @brief JSON işleme ve taktik veri dönüştürme yardımcı fonksiyonları
 * @ingroup json_processing
 * @author Taktik Veri Sistemi
 * @date 2025
 * 
 * Bu dosya JSON parsing, taktik veri dönüştürme ve formatlanmış çıktı
 * üretme fonksiyonlarını içerir. cJSON kütüphanesi kullanarak güvenli
 * ve verimli JSON işleme sağlar.
 * 
 * Ana özellikler:
 * - Genel JSON parsing ve string formatına dönüştürme
 * - Taktik veri (tactical_data_t) struct'ına JSON parsing
 * - Recursive JSON object traversal
 * - Hata toleranslı parsing (default değerler)
 * - Memory management ve güvenli string operations
 * - Zaman damgası işleme ve formatlaması
 * - Detaylı debug çıktıları
 * 
 * Desteklenen JSON formatı (tactical data):
 * @code
 * {
 *   "unit_id": "BIRIM-01",
 *   "status": "AKTIF",
 *   "latitude": 39.925018,
 *   "longitude": 32.866287,
 *   "description": "Taktik durum raporu",
 *   "timestamp": 1640995200
 * }
 * @endcode
 * 
 * @note Tüm fonksiyonlar güvenli bellek yönetimi ve hata kontrolü içerir.
 *       NULL pointer'lar ve geçersiz JSON formatları handle edilir.
 * 
 * @warning cJSON kütüphanesi gereklidir. Bellek sızıntılarını önlemek için
 *          döndürülen string'ler caller tarafından free() edilmelidir.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "json_utils.h"
#include "logger.h"

/**
 * @brief JSON içeriğini parse edip formatlanmış string'e dönüştürür
 * @ingroup json_processing
 * 
 * Bu fonksiyon genel amaçlı JSON parsing yapar ve human-readable
 * format string'i üretir. Tüm JSON tiplerini destekler ve recursive
 * object traversal yapar.
 * 
 * İşlem adımları:
 * 1. Bellek tahsisi yapar (4KB buffer)
 * 2. Header bilgileri ekler (dosya adı, zaman)
 * 3. JSON'u cJSON ile parse eder
 * 4. Recursive traversal ile tüm elementleri işler
 * 5. Formatlanmış sonucu döndürür
 * 
 * Desteklenen JSON tipleri:
 * - String, Number, Boolean, Null
 * - Array (indexed elements)
 * - Object (nested objects)
 * 
 * @param json_content Parse edilecek JSON string'i
 * @param filename İşlenen dosya adı (raporlama için)
 * 
 * @return Başarıda formatlanmış string (malloc'lu)
 * @return Hata durumunda hata mesajı (malloc'lu)
 * 
 * @note Döndürülen string caller tarafından free() edilmelidir.
 *       Buffer boyutu 4KB ile sınırlıdır.
 * 
 * @warning Geçersiz JSON format durumunda hata mesajı döner,
 *          program crash etmez.
 * 
 * @see print_json_recursive()
 * @see get_current_time()
 * 
 * Örnek çıktı:
 * @code
 * JSON Parse Sonucu
 * ================
 * Dosya: test.json
 * Zaman: 14:30:25
 * Parse Edildi:
 * -------------
 * unit_id: "BIRIM-01" (String)
 * status: "AKTIF" (String)
 * latitude: 39.93 (Double)
 * coordinates: Array (2 oge)
 *   [0]: 39.925018
 *   [1]: 32.866287
 * @endcode
 */
// JSON'u parse edip formatli string'e cevir
char* parse_json_to_string(const char* json_content, const char* filename) {
    size_t result_size = 4096;
    char *result = malloc(result_size);
    if (result == NULL) {
        char *error_msg = malloc(64);
        strcpy(error_msg, "HATA: Bellek tahsis hatasi");
        return error_msg;
    }
    
    // Basligi olustur
    char *current_time = get_current_time();
    snprintf(result, result_size, 
             "JSON Parse Sonucu\n"
             "================\n"
             "Dosya: %s\n"
             "Zaman: %s\n"
             "Parse Edildi:\n"
             "-------------\n", 
             filename, current_time);
    free(current_time);
    
    // JSON parse et
    cJSON *json = cJSON_Parse(json_content);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), 
                "HATA: JSON parse edilemedi\nDetay: %s", 
                error_ptr ? error_ptr : "Bilinmeyen hata");
        strcat(result, error_msg);
        return result;
    }
    
    // JSON'u recursive olarak isle
    print_json_recursive(json, result, 0, result_size);
    
    cJSON_Delete(json);
    return result;
}

/**
 * @brief JSON objesini recursive olarak traverse eder ve formatlanmış string üretir
 * @ingroup json_processing
 * 
 * Bu fonksiyon JSON objesinin tüm elementlerini recursive olarak dolaşır
 * ve indent'li, tip bilgisi içeren formatlanmış çıktı üretir.
 * 
 * İşlenen JSON tipleri:
 * - **String**: Çift tırnak içinde, "(String)" etiketi
 * - **Number**: Integer/Double ayrımı, tip etiketi
 * - **Boolean**: true/false değeri, "(Boolean)" etiketi
 * - **Array**: Boyut bilgisi ve indexed elementler
 * - **Object**: Nested object recursive işleme
 * - **Null**: "null" değeri
 * 
 * Özel array işlemi:
 * - Array boyutunu gösterir
 * - Her elementi index ile listeler
 * - Nested array'leri destekler
 * 
 * @param json Traverse edilecek cJSON objesi
 * @param result Sonucun ekleneceği string buffer
 * @param depth Mevcut indent seviyesi (recursive çağrılarda)
 * @param max_size Buffer'ın maksimum boyutu
 * 
 * @note Fonksiyon recursive çalışır, deep nesting'i destekler.
 *       Buffer overflow koruması vardır.
 * 
 * @warning max_size sınırını aşan çıktı kesilir.
 *          Stack overflow riski için çok derin nesting'den kaçının.
 * 
 * @see add_indent()
 * @see parse_json_to_string()
 * 
 * Çıktı formatı:
 * @code
 * unit_id: "BIRIM-01" (String)
 * status: "AKTIF" (String)
 * coordinates: Array (2 oge)
 *   [0]: 39.925018
 *   [1]: 32.866287
 * metadata: Object
 *   priority: 1 (Integer)
 *   urgent: true (Boolean)
 * @endcode
 */
// JSON'u recursive olarak formatli string'e cevir
void print_json_recursive(cJSON *json, char* result, int depth, size_t max_size) {
    cJSON *current_element = NULL;
    char temp[512];
    
    cJSON_ArrayForEach(current_element, json) {
        add_indent(result, depth, max_size);
        
        if (current_element->string != NULL) {
            snprintf(temp, sizeof(temp), "%s: ", current_element->string);
            strncat(result, temp, max_size - strlen(result) - 1);
        }
        
        if (cJSON_IsString(current_element)) {
            snprintf(temp, sizeof(temp), "\"%s\" (String)\n", current_element->valuestring);
        } else if (cJSON_IsNumber(current_element)) {
            if (current_element->valuedouble == (double)current_element->valueint) {
                snprintf(temp, sizeof(temp), "%d (Integer)\n", current_element->valueint);
            } else {
                snprintf(temp, sizeof(temp), "%.2f (Double)\n", current_element->valuedouble);
            }
        } else if (cJSON_IsBool(current_element)) {
            snprintf(temp, sizeof(temp), "%s (Boolean)\n", 
                    cJSON_IsTrue(current_element) ? "true" : "false");
        } else if (cJSON_IsArray(current_element)) {
            snprintf(temp, sizeof(temp), "Array (%d oge)\n", cJSON_GetArraySize(current_element));
            strncat(result, temp, max_size - strlen(result) - 1);
            
            cJSON *array_item = NULL;
            int index = 0;
            cJSON_ArrayForEach(array_item, current_element) {
                add_indent(result, depth + 1, max_size);
                if (cJSON_IsString(array_item)) {
                    snprintf(temp, sizeof(temp), "[%d]: \"%s\"\n", index, array_item->valuestring);
                } else if (cJSON_IsNumber(array_item)) {
                    snprintf(temp, sizeof(temp), "[%d]: %.2f\n", index, array_item->valuedouble);
                } else {
                    snprintf(temp, sizeof(temp), "[%d]: (Diger tip)\n", index);
                }
                strncat(result, temp, max_size - strlen(result) - 1);
                index++;
            }
            continue;
        } else if (cJSON_IsObject(current_element)) {
            snprintf(temp, sizeof(temp), "Object\n");
            strncat(result, temp, max_size - strlen(result) - 1);
            print_json_recursive(current_element, result, depth + 1, max_size);
            continue;
        } else if (cJSON_IsNull(current_element)) {
            snprintf(temp, sizeof(temp), "null\n");
        } else {
            snprintf(temp, sizeof(temp), "Bilinmeyen tip\n");
        }
        
        strncat(result, temp, max_size - strlen(result) - 1);
    }
}

/**
 * @brief JSON output'u için girinti (indent) karakterleri ekler
 * @ingroup json_processing
 * 
 * Recursive JSON parsing sırasında nested structure'ları görsel olarak
 * ayırt etmek için depth'e göre girinti ekler.
 * 
 * @param result Girinti eklenecek string buffer
 * @param depth Girinti seviyesi (her seviye = 2 space)
 * @param max_size Buffer'ın maksimum boyutu
 * 
 * @note Her depth seviyesi için 2 space eklenir.
 *       Buffer overflow koruması vardır.
 * 
 * @warning Çok derin nesting (depth > 30) buffer overflow'a neden olabilir.
 * 
 * @see print_json_recursive()
 */
// Girinti ekle
void add_indent(char* result, int depth, size_t max_size) {
    char indent[64] = "";
    for (int i = 0; i < depth; i++) {
        strcat(indent, "  ");
    }
    strncat(result, indent, max_size - strlen(result) - 1);
}

/**
 * @brief Mevcut sistem zamanını HH:MM:SS formatında getirir
 * @ingroup json_processing
 * 
 * Zaman damgası ve log mesajları için kullanılan utility fonksiyon.
 * Locale time zone'unu kullanır.
 * 
 * @return Mevcut zaman string'i "HH:MM:SS" formatında (malloc'lu)
 * 
 * @note Döndürülen string caller tarafından free() edilmelidir.
 *       32 byte buffer kullanır.
 * 
 * @see parse_json_to_string()
 * @see tactical_data_to_string()
 * 
 * Örnek dönen değer: "14:30:25"
 */
// Mevcut zamayi al
char* get_current_time(void) {
    time_t rawtime;
    struct tm *timeinfo;
    char *time_str = malloc(32);
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    snprintf(time_str, 32, "%02d:%02d:%02d", 
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    
    return time_str;
}

/**
 * @brief JSON'u tactical_data_t struct'ına parse eder - ana taktik veri işleme fonksiyonu
 * @ingroup json_processing
 * 
 * Bu fonksiyon taktik veri JSON formatını tactical_data_t struct'ına
 * dönüştürür. Production sistem için kritik fonksiyondur.
 * 
 * Parse edilen alanlar:
 * - **unit_id**: Askeri birim kimliği (string, zorunlu)
 * - **status**: Birim durumu (string, zorunlu)
 * - **latitude**: Enlem koordinatı (double, zorunlu)
 * - **longitude**: Boylam koordinatı (double, zorunlu)  
 * - **description**: Detay açıklama (string, opsiyonel)
 * - **timestamp**: Zaman damgası (long, opsiyonel)
 * 
 * Hata toleransı:
 * - Eksik alanlar için default değerler atanır
 * - Geçersiz tipler için güvenli fallback'ler
 * - Parse hatalarında uyarı mesajları
 * - Timestamp eksikse mevcut zaman kullanılır
 * 
 * İşlem adımları:
 * 1. Memory allocation ve struct initialization
 * 2. JSON parse ve geçerlilik kontrolü
 * 3. Her alanı güvenli şekilde extract etme
 * 4. Type checking ve conversion
 * 5. Buffer overflow koruması
 * 6. Validation ve debug çıktısı
 * 
 * @param json_content Parse edilecek JSON string'i
 * @param filename İşlenen dosya adı (debug için)
 * 
 * @return Başarıda tactical_data_t pointer (malloc'lu)
 * @return Parse hatası durumunda NULL
 * 
 * @note Döndürülen struct caller tarafından free_tactical_data() ile temizlenmelidir.
 *       is_valid flag'i parse başarısını gösterir.
 * 
 * @warning NULL return değeri kontrol edilmelidir.
 *          Buffer boyutları (unit_id, status, description) sınırlıdır.
 * 
 * Default değerler:
 * - unit_id: "UNKNOWN"
 * - status: "UNKNOWN"  
 * - latitude/longitude: 0.0
 * - description: "Açıklama yok"
 * - timestamp: current time
 * 
 * @see free_tactical_data()
 * @see tactical_data_to_string()
 * 
 * Örnek JSON formatı:
 * @code
 * {
 *   "unit_id": "BIRIM-01",
 *   "status": "OPERASYONEL", 
 *   "latitude": 39.925018,
 *   "longitude": 32.866287,
 *   "description": "Rutin devriye görevi",
 *   "timestamp": 1640995200
 * }
 * @endcode
 * 
 * Debug çıktısı:
 * @code
 * JSON başarıyla tactical_data_t'ye parse edildi:
 *   - Unit ID: BIRIM-01
 *   - Status: OPERASYONEL
 *   - Konum: 39.925018, 32.866287
 *   - Açıklama: Rutin devriye görevi
 *   - Timestamp: 1640995200
 * @endcode
 */
// JSON'u tactical_data_t struct'ına parse et
tactical_data_t* parse_json_to_tactical_data(const char* json_content, const char* filename) {
    tactical_data_t* data = malloc(sizeof(tactical_data_t));
    if (data == NULL) {
        return NULL;
    }
    
    // Initialize data structure
    memset(data, 0, sizeof(tactical_data_t));
    data->is_valid = 0;
    
    // JSON parse et
    cJSON *json = cJSON_Parse(json_content);
    if (json == NULL) {
        PRINTF_LOG("HATA: JSON parse edilemedi - %s\n", filename);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            PRINTF_LOG("Parse hatası: %s\n", error_ptr);
        }
        free(data);
        return NULL;
    }
    
    // unit_id field'ını parse et
    cJSON *unit_id = cJSON_GetObjectItemCaseSensitive(json, "unit_id");
    if (cJSON_IsString(unit_id) && (unit_id->valuestring != NULL)) {
        strncpy(data->unit_id, unit_id->valuestring, sizeof(data->unit_id) - 1);
        data->unit_id[sizeof(data->unit_id) - 1] = '\0';
    } else {
        PRINTF_LOG("UYARI: unit_id field'ı bulunamadı veya geçersiz\n");
        strcpy(data->unit_id, "UNKNOWN");
    }
    
    // status field'ını parse et
    cJSON *status = cJSON_GetObjectItemCaseSensitive(json, "status");
    if (cJSON_IsString(status) && (status->valuestring != NULL)) {
        strncpy(data->status, status->valuestring, sizeof(data->status) - 1);
        data->status[sizeof(data->status) - 1] = '\0';
    } else {
        PRINTF_LOG("UYARI: status field'ı bulunamadı veya geçersiz\n");
        strcpy(data->status, "UNKNOWN");
    }
    
    // latitude field'ını parse et
    cJSON *latitude = cJSON_GetObjectItemCaseSensitive(json, "latitude");
    if (cJSON_IsNumber(latitude)) {
        data->latitude = latitude->valuedouble;
    } else {
        PRINTF_LOG("UYARI: latitude field'ı bulunamadı veya geçersiz\n");
        data->latitude = 0.0;
    }
    
    // longitude field'ını parse et
    cJSON *longitude = cJSON_GetObjectItemCaseSensitive(json, "longitude");
    if (cJSON_IsNumber(longitude)) {
        data->longitude = longitude->valuedouble;
    } else {
        PRINTF_LOG("UYARI: longitude field'ı bulunamadı veya geçersiz\n");
        data->longitude = 0.0;
    }
    
    // description field'ını parse et
    cJSON *description = cJSON_GetObjectItemCaseSensitive(json, "description");
    if (cJSON_IsString(description) && (description->valuestring != NULL)) {
        strncpy(data->description, description->valuestring, sizeof(data->description) - 1);
        data->description[sizeof(data->description) - 1] = '\0';
    } else {
        PRINTF_LOG("UYARI: description field'ı bulunamadı veya geçersiz\n");
        strcpy(data->description, "Açıklama yok");
    }
    
    // timestamp field'ını parse et
    cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(json, "timestamp");
    if (cJSON_IsNumber(timestamp)) {
        data->timestamp = (long)timestamp->valuedouble;
    } else {
        PRINTF_LOG("UYARI: timestamp field'ı bulunamadı veya geçersiz\n");
        data->timestamp = time(NULL); // Current time as fallback
    }
    
    data->is_valid = 1;
    cJSON_Delete(json);
    
    PRINTF_LOG("JSON başarıyla tactical_data_t'ye parse edildi:\n");
    PRINTF_LOG("  - Unit ID: %s\n", data->unit_id);
    PRINTF_LOG("  - Status: %s\n", data->status);
    PRINTF_LOG("  - Konum: %.6f, %.6f\n", data->latitude, data->longitude);
    PRINTF_LOG("  - Açıklama: %.50s%s\n", data->description, 
           strlen(data->description) > 50 ? "..." : "");
    PRINTF_LOG("  - Timestamp: %ld\n", data->timestamp);
    
    return data;
}

/**
 * @brief Tactical data struct'ını detaylı formatlanmış rapora dönüştürür
 * @ingroup json_processing
 * 
 * Bu fonksiyon tactical_data_t struct'ından professional taktik veri
 * raporu üretir. Client'a gönderilecek response formatında çıktı sağlar.
 * 
 * Rapor bölümleri:
 * - **Header**: Dosya adı ve parse zamanı
 * - **Tactical Data Details**: Tüm veri alanları
 * - **Durum Analizi**: Veri geçerliliği ve doğruluk kontrolleri
 * - **Koordinat Bilgileri**: Enlem/boylam formatları
 * - **Zaman Bilgileri**: Unix timestamp ve human-readable format
 * 
 * Analiz edilen kriterler:
 * - Veri geçerliliği (is_valid flag)
 * - Koordinat doğruluğu (sıfır kontrolü)
 * - Açıklama uzunluğu
 * - Timestamp formatlaması
 * 
 * @param data Formatlanacak tactical_data_t struct'ı
 * @param filename Raporda gösterilecek dosya adı
 * 
 * @return Başarıda detaylı rapor string'i (malloc'lu)
 * @return Geçersiz data durumunda hata mesajı (malloc'lu)
 * 
 * @note Döndürülen string caller tarafından free() edilmelidir.
 *       2KB buffer boyutu limiti vardır.
 * 
 * @warning data NULL veya is_valid=false ise hata mesajı döner.
 *          Bellek tahsisi başarısızlığında hata mesajı döner.
 * 
 * @see parse_json_to_tactical_data()
 * @see get_current_time()
 * @see free_tactical_data()
 * 
 * Örnek rapor çıktısı:
 * @code
 * Tactical Data Parse Sonucu
 * ==========================
 * Dosya: mission_data.json
 * Parse Zamanı: 14:30:25
 * 
 * TACTICAL DATA DETAYLARI:
 * ------------------------
 * Birim ID       : BIRIM-01
 * Durum          : OPERASYONEL
 * Enlem          : 39.925018°
 * Boylam         : 32.866287°
 * Konum          : 39.925018°N, 32.866287°E
 * Açıklama       : Rutin devriye görevi devam ediyor
 * Zaman Damgası  : 1640995200 (2021-12-31 12:00:00)
 * 
 * DURUM ANALİZİ:
 * -------------
 * Veri Geçerliliği: GEÇERLI
 * Koordinat Doğruluğu: DOĞRU
 * Açıklama Uzunluğu: 28 karakter
 * 
 * ==========================
 * @endcode
 */
// Tactical data'yı formatted string'e çevir
char* tactical_data_to_string(const tactical_data_t* data, const char* filename) {
    if (data == NULL || !data->is_valid) {
        char *error_msg = malloc(128);
        strcpy(error_msg, "HATA: Geçersiz tactical data");
        return error_msg;
    }
    
    size_t result_size = 2048;
    char *result = malloc(result_size);
    if (result == NULL) {
        char *error_msg = malloc(64);
        strcpy(error_msg, "HATA: Bellek tahsis hatası");
        return error_msg;
    }
    
    char *current_time = get_current_time();
    
    // Timestamp'i human readable formata çevir
    char timestamp_str[64];
    time_t ts = data->timestamp;
    struct tm *timeinfo = localtime(&ts);
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    snprintf(result, result_size,
             "Tactical Data Parse Sonucu\n"
             "==========================\n"
             "Dosya: %s\n"
             "Parse Zamanı: %s\n"
             "\n"
             "TACTICAL DATA DETAYLARI:\n"
             "------------------------\n"
             "Birim ID       : %s\n"
             "Durum          : %s\n"
             "Enlem          : %.6f°\n"
             "Boylam         : %.6f°\n"
             "Konum          : %.6f°N, %.6f°E\n"
             "Açıklama       : %s\n"
             "Zaman Damgası  : %ld (%s)\n"
             "\n"
             "DURUM ANALİZİ:\n"
             "-------------\n"
             "Veri Geçerliliği: %s\n"
             "Koordinat Doğruluğu: %s\n"
             "Açıklama Uzunluğu: %zu karakter\n"
             "\n"
             "==========================\n",
             filename,
             current_time,
             data->unit_id,
             data->status,
             data->latitude,
             data->longitude,
             data->latitude,
             data->longitude,
             data->description,
             data->timestamp,
             timestamp_str,
             data->is_valid ? "GEÇERLI" : "GEÇERSİZ",
             (data->latitude != 0.0 && data->longitude != 0.0) ? "DOĞRU" : "HATALI",
             strlen(data->description)
    );
    
    free(current_time);
    return result;
}

/**
 * @brief Tactical data struct'ının belleğini güvenli şekilde temizler
 * @ingroup json_processing
 * 
 * parse_json_to_tactical_data() fonksiyonu ile oluşturulan
 * tactical_data_t struct'ının belleğini serbest bırakır.
 * 
 * @param data Temizlenecek tactical_data_t pointer'ı
 * 
 * @note NULL pointer kontrolü yapar, güvenli çağrım sağlar.
 *       Memory leak'leri önlemek için mutlaka çağrılmalıdır.
 * 
 * @warning Bu fonksiyondan sonra data pointer'ı geçersiz hale gelir.
 * 
 * @see parse_json_to_tactical_data()
 * 
 * Kullanım örneği:
 * @code
 * tactical_data_t* data = parse_json_to_tactical_data(json, "file.json");
 * if (data != NULL) {
 *     // data kullanımı
 *     free_tactical_data(data);
 *     data = NULL; // Güvenlik için
 * }
 * @endcode
 */
// Tactical data memory'sini temizle
void free_tactical_data(tactical_data_t* data) {
    if (data != NULL) {
        free(data);
    }
}