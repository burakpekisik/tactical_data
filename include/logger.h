#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

/**
 * @brief Log seviyelerini tanımlar
 */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} log_level_t;

/**
 * @brief Logger türlerini tanımlar (client veya server)
 */
typedef enum {
    LOGGER_CLIENT = 0,
    LOGGER_SERVER = 1
} logger_type_t;

/**
 * @brief Logger yapısı
 */
typedef struct {
    FILE *file;
    char *filename;
    log_level_t min_level;
    logger_type_t type;
    char session_id[32];
} logger_t;

// Global logger instances
extern logger_t *client_logger;
extern logger_t *server_logger;

/**
 * @brief Logger'ı başlatır
 * @param type Logger türü (CLIENT veya SERVER)
 * @param min_level Minimum log seviyesi
 * @return 0 başarılı, -1 hata
 */
int logger_init(logger_type_t type, log_level_t min_level);

/**
 * @brief Logger'ı kapatır
 * @param type Logger türü
 */
void logger_cleanup(logger_type_t type);

/**
 * @brief Log mesajı yazar
 * @param type Logger türü
 * @param level Log seviyesi
 * @param format Format string
 * @param ... Değişken argümanlar
 */
void logger_log(logger_type_t type, log_level_t level, const char *format, ...);

// Convenience macros
#define LOG_CLIENT_DEBUG(fmt, ...) logger_log(LOGGER_CLIENT, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_CLIENT_INFO(fmt, ...)  logger_log(LOGGER_CLIENT, LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_CLIENT_WARN(fmt, ...)  logger_log(LOGGER_CLIENT, LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_CLIENT_ERROR(fmt, ...) logger_log(LOGGER_CLIENT, LOG_ERROR, fmt, ##__VA_ARGS__)

#define LOG_SERVER_DEBUG(fmt, ...) logger_log(LOGGER_SERVER, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_SERVER_INFO(fmt, ...)  logger_log(LOGGER_SERVER, LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_SERVER_WARN(fmt, ...)  logger_log(LOGGER_SERVER, LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_SERVER_ERROR(fmt, ...) logger_log(LOGGER_SERVER, LOG_ERROR, fmt, ##__VA_ARGS__)

// Console logging macros (prints to both console and log file)
#define PRINTF_CLIENT(fmt, ...) logger_printf(LOGGER_CLIENT, fmt, ##__VA_ARGS__)
#define PRINTF_SERVER(fmt, ...) logger_printf(LOGGER_SERVER, fmt, ##__VA_ARGS__)

// Ortak kullanım için console logging macro
#define PRINTF_LOG(fmt, ...) logger_printf_common(fmt, ##__VA_ARGS__)

/**
 * @brief Session ID'yi set eder
 * @param type Logger türü
 * @param session_id Session ID string'i
 */
void logger_set_session_id(logger_type_t type, const char *session_id);

/**
 * @brief Timestamp string'i oluşturur
 * @param buffer Buffer to write timestamp
 * @param buffer_size Buffer boyutu
 */
void logger_get_timestamp(char *buffer, size_t buffer_size);

/**
 * @brief Console çıktısını da log dosyasına yazar
 * @param type Logger türü
 * @param format Format string
 * @param ... Değişken argümanlar
 */
void logger_printf(logger_type_t type, const char *format, ...);

/**
 * @brief Ortak kullanım için console çıktısını tüm aktif logger'lara yazar
 * @param format Format string
 * @param ... Değişken argümanlar
 */
void logger_printf_common(const char *format, ...);

#endif // LOGGER_H
