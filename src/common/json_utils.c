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