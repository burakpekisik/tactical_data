#ifndef _JSON_UTILS_H_
#define _JSON_UTILS_H_

#include <cjson/cJSON.h>
#include "database.h"  // Database fonksiyonları için

// Forward declaration - tactical_data_t database.h'de tanımlı
// struct tanımı database.h'de mevcut

// Function prototypes
char* parse_json_to_string(const char* json_content, const char* filename);
tactical_data_t* parse_json_to_tactical_data(const char* json_content, const char* filename, const char* user_id);
char* tactical_data_to_string(const tactical_data_t* data, const char* filename);
void print_json_recursive(cJSON *json, char* result, int depth, size_t max_size);
void add_indent(char* result, int depth, size_t max_size);
char* get_current_time(void);
void free_tactical_data(tactical_data_t* data);
cJSON* parse_tactical_data_to_json(const tactical_data_t* data);

typedef struct {
    int report_id;
    char msg[512];
    int is_valid;
} admin_reply_t;

admin_reply_t* parse_admin_reply_json(const char* json_content);

// Dispatcher fonksiyon prototipi (void* döner, çağıran uygun struct'a cast etmeli)
void* parse_json_by_type(const char* filename, const char* json_content, const char* user_id);

#endif // _JSON_UTILS_H_