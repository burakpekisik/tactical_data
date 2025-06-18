#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "json_utils.h"

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

// Girinti ekle
void add_indent(char* result, int depth, size_t max_size) {
    char indent[64] = "";
    for (int i = 0; i < depth; i++) {
        strcat(indent, "  ");
    }
    strncat(result, indent, max_size - strlen(result) - 1);
}

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
        printf("HATA: JSON parse edilemedi - %s\n", filename);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            printf("Parse hatası: %s\n", error_ptr);
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
        printf("UYARI: unit_id field'ı bulunamadı veya geçersiz\n");
        strcpy(data->unit_id, "UNKNOWN");
    }
    
    // status field'ını parse et
    cJSON *status = cJSON_GetObjectItemCaseSensitive(json, "status");
    if (cJSON_IsString(status) && (status->valuestring != NULL)) {
        strncpy(data->status, status->valuestring, sizeof(data->status) - 1);
        data->status[sizeof(data->status) - 1] = '\0';
    } else {
        printf("UYARI: status field'ı bulunamadı veya geçersiz\n");
        strcpy(data->status, "UNKNOWN");
    }
    
    // latitude field'ını parse et
    cJSON *latitude = cJSON_GetObjectItemCaseSensitive(json, "latitude");
    if (cJSON_IsNumber(latitude)) {
        data->latitude = latitude->valuedouble;
    } else {
        printf("UYARI: latitude field'ı bulunamadı veya geçersiz\n");
        data->latitude = 0.0;
    }
    
    // longitude field'ını parse et
    cJSON *longitude = cJSON_GetObjectItemCaseSensitive(json, "longitude");
    if (cJSON_IsNumber(longitude)) {
        data->longitude = longitude->valuedouble;
    } else {
        printf("UYARI: longitude field'ı bulunamadı veya geçersiz\n");
        data->longitude = 0.0;
    }
    
    // description field'ını parse et
    cJSON *description = cJSON_GetObjectItemCaseSensitive(json, "description");
    if (cJSON_IsString(description) && (description->valuestring != NULL)) {
        strncpy(data->description, description->valuestring, sizeof(data->description) - 1);
        data->description[sizeof(data->description) - 1] = '\0';
    } else {
        printf("UYARI: description field'ı bulunamadı veya geçersiz\n");
        strcpy(data->description, "Açıklama yok");
    }
    
    // timestamp field'ını parse et
    cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(json, "timestamp");
    if (cJSON_IsNumber(timestamp)) {
        data->timestamp = (long)timestamp->valuedouble;
    } else {
        printf("UYARI: timestamp field'ı bulunamadı veya geçersiz\n");
        data->timestamp = time(NULL); // Current time as fallback
    }
    
    data->is_valid = 1;
    cJSON_Delete(json);
    
    printf("JSON başarıyla tactical_data_t'ye parse edildi:\n");
    printf("  - Unit ID: %s\n", data->unit_id);
    printf("  - Status: %s\n", data->status);
    printf("  - Konum: %.6f, %.6f\n", data->latitude, data->longitude);
    printf("  - Açıklama: %.50s%s\n", data->description, 
           strlen(data->description) > 50 ? "..." : "");
    printf("  - Timestamp: %ld\n", data->timestamp);
    
    return data;
}

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

// Tactical data memory'sini temizle
void free_tactical_data(tactical_data_t* data) {
    if (data != NULL) {
        free(data);
    }
}