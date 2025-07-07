#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>
#include <cjson/cJSON.h>
#include "config.h"
#include "logger.h"
#include "json_utils.h"
#include "database.h"
#include "admin_notify_manager.h"
#include "tactical_data_handler.h"

// Tactical data ENCRYPTED handler
void handle_encrypted_tactical_data(const char* decrypted_json, const char* jwt_token, const char* filename, int client_socket, const char* client_ip, int client_port, char* out, size_t out_size) {
    char user_id_from_jwt[64] = "";
    if (jwt_token) {
        jwt_t *jwt_ptr = NULL;
        int decode_result = jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
        PRINTF_LOG("[DEBUG] jwt_decode sonucu: %d\n", decode_result);
        if (decode_result == 0 && jwt_ptr) {
            const char* sub = jwt_get_grant(jwt_ptr, "sub");
            PRINTF_LOG("[DEBUG] JWT sub: %s\n", sub ? sub : "(null)");
            if (sub) strncpy(user_id_from_jwt, sub, sizeof(user_id_from_jwt) - 1);
            jwt_free(jwt_ptr);
        }
    }
    PRINTF_LOG("Decrypted JSON: %s\n", decrypted_json);
    tactical_data_t* tactical_data = parse_json_to_tactical_data(decrypted_json, filename, user_id_from_jwt);
    PRINTF_LOG("[DEBUG] tactical_data: report_id=%d, user_id=%s, is_valid=%d\n", tactical_data ? tactical_data->report_id : -1, tactical_data && tactical_data->user_id ? tactical_data->user_id : "(null)", tactical_data ? tactical_data->is_valid : -1);
    if (tactical_data != NULL && tactical_data->is_valid) {
        char* db_result = db_save_tactical_data_and_get_response(tactical_data, filename);
        cJSON* report_json_obj = parse_tactical_data_to_json(tactical_data);
        char* report_json = cJSON_Print(report_json_obj);
        int sender_privilege = 0;
        if (jwt_token) {
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                sender_privilege = jwt_get_grant_int(jwt_ptr, "privilege");
                jwt_free(jwt_ptr);
            }
        }
        if (client_socket >= 0) {
            admin_notify_manager_notify_admins(report_json, client_socket, sender_privilege);
        } else {
            PRINTF_LOG("[ADMIN_NOTIFY] UDP/P2P için admin bildirimi: ip=%s, port=%d\n", client_ip ? client_ip : "(null)", client_port);
        }
        cJSON_Delete(report_json_obj);
        if (report_json) free(report_json);
        if (db_result) {
            strncpy(out, db_result, out_size - 1);
            out[out_size - 1] = '\0';
            free(db_result);
        } else {
            snprintf(out, out_size, "{\"error\":\"Veritabanı kaydı başarısız\"}");
        }
        free_tactical_data(tactical_data);
    } else {
        snprintf(out, out_size, "HATA: Decrypted JSON tactical data formatına uygun değil");
        if (tactical_data) free_tactical_data(tactical_data);
    }
}