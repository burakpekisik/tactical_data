#include "info_handler.h"
#include "logger.h"
#include "jwt_manager.h"

// Bilgi sorgusu için handler fonksiyonu
// conn: client_connection_t* (oturum bilgisi), jwt_token: kimlik doğrulama token'ı
// Gerekirse ek parametreler eklenebilir
int handle_info_request(const char* jwt_token, char* out_buf, size_t out_buf_size) {
    PRINTF_LOG("[INFO_HANDLER] handle_info_request çağrıldı\n");
    if (!jwt_token || !out_buf || out_buf_size == 0) {
        PRINTF_CLIENT("[INFO_HANDLER] Geçersiz parametre!\n");
        return -1;
    }
    char* info = jwt_get_my_information(jwt_token);
    if (info) {
        snprintf(out_buf, out_buf_size, "%s", info);
        PRINTF_LOG("[INFO_HANDLER] Kullanıcı bilgisi başarıyla alındı: %s\n", info);
        free(info);
        return 0;
    } else {
        snprintf(out_buf, out_buf_size, "{\"error\":\"Kullanıcı bilgisi alınamadı\"}");
        PRINTF_CLIENT("[INFO_HANDLER] Kullanıcı bilgisi alınamadı!\n");
        return -1;
    }
}
