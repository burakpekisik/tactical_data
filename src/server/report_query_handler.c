#include "report_query_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jwt.h>
#include <time.h>
#include "database.h"
#include "jwt_manager.h"
#include "config.h"
#include "logger.h"

// JSON oluşturmak için cJSON kullanmak daha güvenli olur, örnek düz string ile
int handle_report_query(const char* jwt_token, char* out_json, size_t out_json_size) {
    LOG_SERVER_INFO("[REPORT_QUERY] handle_report_query çağrıldı, jwt_token: %s", jwt_token ? jwt_token : "(null)");
    if (verify_jwt(jwt_token) != 0) {
        LOG_SERVER_ERROR("[REPORT_QUERY] JWT doğrulama başarısız! Token: %s", jwt_token ? jwt_token : "(null)");
        snprintf(out_json, out_json_size, "{\"error\":\"Invalid JWT\"}");
        return -1;
    }
    jwt_t *jwt;
    int decode_result = jwt_decode(&jwt, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    LOG_SERVER_INFO("[REPORT_QUERY] jwt_decode result: %d", decode_result);
    if (decode_result != 0) {
        LOG_SERVER_ERROR("[REPORT_QUERY] jwt_decode başarısız! Token: %s", jwt_token ? jwt_token : "(null)");
        snprintf(out_json, out_json_size, "{\"error\":\"JWT decode failed\"}");
        return -1;
    }
    int privilege = jwt_get_grant_int(jwt, "privilege");
    const char* sub_str = jwt_get_grant(jwt, "sub");
    int user_id = sub_str ? atoi(sub_str) : -1;
    LOG_SERVER_INFO("[REPORT_QUERY] JWT payload: privilege=%d, user_id=%d (sub=%s)", privilege, user_id, sub_str ? sub_str : "(null)");
    report_t *reports = NULL;
    int report_count = 0;
    if (privilege == ADMIN_PRIVILEGE) {
        LOG_SERVER_INFO("[REPORT_QUERY] ADMIN_PRIVILEGE, tüm raporlar çekiliyor");
        db_select_reports(&reports, &report_count);
    } else {
        LOG_SERVER_INFO("[REPORT_QUERY] USER_PRIVILEGE, user_id=%d için raporlar çekiliyor", user_id);
        db_select_reports_by_user(user_id, &reports, &report_count);
    }
    LOG_SERVER_INFO("[REPORT_QUERY] Toplam rapor sayısı: %d", report_count);
    // JSON cevabı oluştur
    char* ptr = out_json;
    size_t used = 0;
    used += snprintf(ptr + used, out_json_size - used, "{\"privilege\":%d,\"reports\":[", privilege);
    for (int i = 0; i < report_count; ++i) {
        char entry[2048];
        snprintf(entry, sizeof(entry),
            "{\"id\":%d,\"user_id\":%d,\"status\":\"%s\",\"latitude\":%.6f,\"longitude\":%.6f,\"description\":\"%s\",\"timestamp\":%ld}",
            reports[i].id, reports[i].user_id, reports[i].status, reports[i].latitude, reports[i].longitude, reports[i].description, reports[i].timestamp);
        used += snprintf(ptr + used, out_json_size - used, "%s%s", entry, (i < report_count - 1) ? "," : "");
        if (used >= out_json_size) {
            LOG_SERVER_ERROR("[REPORT_QUERY] JSON buffer overflow! used=%zu, out_json_size=%zu", used, out_json_size);
            break;
        }
    }
    snprintf(ptr + used, out_json_size - used, "]}");
    LOG_SERVER_INFO("[REPORT_QUERY] JSON cevabı hazır, uzunluk: %zu", strlen(out_json));
    if (reports) free(reports);
    jwt_free(jwt);
    return 0;
}