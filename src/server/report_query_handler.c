#include "report_query_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jwt.h>
#include "database.h"
#include "jwt_manager.h"
#include "config.h"
#include "logger.h"

// JSON oluşturmak için cJSON kullanmak daha güvenli olur, örnek düz string ile
int handle_report_query(const char* jwt_token, char* out_json, size_t out_json_size) {
    if (verify_jwt(jwt_token) != 0) {
        snprintf(out_json, out_json_size, "{\"error\":\"Invalid JWT\"}");
        return -1;
    }
    jwt_t *jwt;
    jwt_decode(&jwt, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    int privilege = jwt_get_grant_int(jwt, "privilege");
    int user_id = atoi(jwt_get_grant(jwt, "sub"));

    report_t *reports = NULL;
    int report_count = 0;
    if (privilege == ADMIN_PRIVILEGE) {
        db_select_reports(&reports, &report_count);
    } else {
        db_select_reports_by_user(user_id, &reports, &report_count);
    }

    // JSON cevabı oluştur
    char* ptr = out_json;
    size_t used = 0;
    used += snprintf(ptr + used, out_json_size - used, "[");
    for (int i = 0; i < report_count; ++i) {
        char entry[2048];
        snprintf(entry, sizeof(entry),
            "{\"id\":%d,\"user_id\":%d,\"status\":\"%s\",\"latitude\":%.6f,\"longitude\":%.6f,\"description\":\"%s\",\"timestamp\":%ld}",
            reports[i].id, reports[i].user_id, reports[i].status, reports[i].latitude, reports[i].longitude, reports[i].description, reports[i].timestamp);
        used += snprintf(ptr + used, out_json_size - used, "%s%s", entry, (i < report_count - 1) ? "," : "");
        if (used >= out_json_size) break;
    }
    snprintf(ptr + used, out_json_size - used, "]");
    if (reports) free(reports);
    jwt_free(jwt);
    return 0;
}

// Buffer büyütme için öneri: encrypted_server.c'de çağrılırken de büyük buffer kullanılmalı.
