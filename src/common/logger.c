#include "logger.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

// Global logger instances
logger_t *client_logger = NULL;
logger_t *server_logger = NULL;

// Log level strings
static const char* log_level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

/**
 * @brief Log dizini oluşturur
 */
static int create_log_directory() {
    struct stat st = {0};
    
    if (stat("logs", &st) == -1) {
        if (mkdir("logs", 0755) != 0) {
            fprintf(stderr, "Failed to create logs directory: %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Session ID oluşturur
 */
static void generate_session_id(char *session_id, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    snprintf(session_id, size, "%04d%02d%02d_%02d%02d%02d_%d",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, getpid());
}

/**
 * @brief Logger dosya adı oluşturur
 */
static void create_log_filename(logger_type_t type, char *filename, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    const char *prefix = (type == LOGGER_CLIENT) ? "client" : "server";
    
    snprintf(filename, size, "logs/%s_%04d%02d%02d_%02d%02d%02d_%d.log",
             prefix,
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, getpid());
}

/**
 * @brief Timestamp string'i oluşturur
 * @param buffer Timestamp'in yazılacağı buffer
 * @param buffer_size Buffer boyutu
 */
void logger_get_timestamp(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * @brief Logger'ı başlatır ve dosya sistemini hazırlar
 * @param type Logger türü (CLIENT veya SERVER)
 * @param min_level Minimum log seviyesi (DEBUG, INFO, WARN, ERROR)
 * @return 0 işlem başarılı, -1 hata durumunda
 * @details Bu fonksiyon log dizinini oluşturur, logger yapısını memory'de allocate eder,
 *          log dosyasını açar ve global logger pointer'ını set eder
 */
int logger_init(logger_type_t type, log_level_t min_level) {
    // Log dizini oluştur
    if (create_log_directory() != 0) {
        return -1;
    }
    
    // Logger'ı oluştur
    logger_t *logger = malloc(sizeof(logger_t));
    if (!logger) {
        fprintf(stderr, "Failed to allocate memory for logger\n");
        return -1;
    }
    
    // Dosya adı oluştur
    logger->filename = malloc(256);
    if (!logger->filename) {
        fprintf(stderr, "Failed to allocate memory for filename\n");
        free(logger);
        return -1;
    }
    
    create_log_filename(type, logger->filename, 256);
    
    // Dosyayı aç
    logger->file = fopen(logger->filename, "a");
    if (!logger->file) {
        fprintf(stderr, "Failed to open log file %s: %s\n", logger->filename, strerror(errno));
        free(logger->filename);
        free(logger);
        return -1;
    }
    
    // Logger ayarlarını set et
    logger->min_level = min_level;
    logger->type = type;
    generate_session_id(logger->session_id, sizeof(logger->session_id));
    
    // Global pointer'ı set et
    if (type == LOGGER_CLIENT) {
        client_logger = logger;
    } else {
        server_logger = logger;
    }
    
    // Başlangıç mesajı
    logger_log(type, LOG_INFO, "Logger initialized - Session ID: %s", logger->session_id);
    
    return 0;
}

/**
 * @brief Logger'ı kapatır ve kaynakları temizler
 * @param type Logger türü (CLIENT veya SERVER)
 * @details Logger dosyasını kapatır, allocate edilmiş memory'yi serbest bırakır
 *          ve global logger pointer'ını NULL yapar
 */
void logger_cleanup(logger_type_t type) {
    logger_t *logger = (type == LOGGER_CLIENT) ? client_logger : server_logger;
    
    if (logger) {
        logger_log(type, LOG_INFO, "Logger shutting down - Session ID: %s", logger->session_id);
        
        if (logger->file) {
            fclose(logger->file);
        }
        
        if (logger->filename) {
            free(logger->filename);
        }
        
        free(logger);
        
        if (type == LOGGER_CLIENT) {
            client_logger = NULL;
        } else {
            server_logger = NULL;
        }
    }
}

/**
 * @brief Belirtilen seviyede log mesajı yazar
 * @param type Logger türü (CLIENT veya SERVER)
 * @param level Log seviyesi (DEBUG, INFO, WARN, ERROR)
 * @param format Printf-style format string
 * @param ... Değişken argümanlar
 * @details Minimum log seviyesi kontrolü yapar, timestamp ekler,
 *          WARN ve ERROR seviyelerinde console'a da çıktı verir
 */
void logger_log(logger_type_t type, log_level_t level, const char *format, ...) {
    logger_t *logger = (type == LOGGER_CLIENT) ? client_logger : server_logger;
    
    if (!logger || !logger->file) {
        return;
    }
    
    // Minimum seviye kontrolü
    if (level < logger->min_level) {
        return;
    }
    
    // Timestamp oluştur
    char timestamp[64];
    logger_get_timestamp(timestamp, sizeof(timestamp));
    
    // Log prefixini oluştur
    const char *type_str = (type == LOGGER_CLIENT) ? "CLIENT" : "SERVER";
    const char *level_str = log_level_strings[level];
    
    // Process ID'yi al
    pid_t pid = getpid();
    
    // Format string'i hazırla
    va_list args;
    va_start(args, format);
    
    // Log dosyasına yaz
    fprintf(logger->file, "[%s] [%s] [%s] [PID:%d] [SID:%s] ", 
            timestamp, type_str, level_str, pid, logger->session_id);
    vfprintf(logger->file, format, args);
    fprintf(logger->file, "\n");
    
    // Her log yazımından sonra buffer'ı flush et (Qt uyumluluğu için)
    fflush(logger->file);
    
    // Debug modda console'a da yazdır
    if (level >= LOG_WARN) {
        fprintf(stderr, "[%s] [%s] [%s] ", timestamp, type_str, level_str);
        va_start(args, format);
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
    }
    
    va_end(args);
}

/**
 * @brief Logger'ın session ID'sini günceller
 * @param type Logger türü (CLIENT veya SERVER)
 * @param session_id Yeni session ID string'i
 * @details Session ID'yi güvenli bir şekilde kopyalar ve güncelleme logunu yazar
 */
void logger_set_session_id(logger_type_t type, const char *session_id) {
    logger_t *logger = (type == LOGGER_CLIENT) ? client_logger : server_logger;
    
    if (logger && session_id) {
        strncpy(logger->session_id, session_id, sizeof(logger->session_id) - 1);
        logger->session_id[sizeof(logger->session_id) - 1] = '\0';
        logger_log(type, LOG_INFO, "Session ID updated to: %s", logger->session_id);
    }
}

/**
 * @brief Console çıktısını hem ekrana hem de belirtilen logger dosyasına yazar
 * @param type Logger türü (CLIENT veya SERVER)
 * @param format Printf-style format string
 * @param ... Değişken argümanlar
 * @details Printf işlevselliğini sağlar, çıktıyı hem console'a hem de
 *          ilgili logger dosyasına CONSOLE etiketi ile yazar
 */
void logger_printf(logger_type_t type, const char *format, ...) {
    logger_t *logger = (type == LOGGER_CLIENT) ? client_logger : server_logger;
    
    va_list args;
    va_start(args, format);
    
    // Console'a yazdır
    vprintf(format, args);
    fflush(stdout);
    
    // Log dosyasına da yazdır (eğer logger aktifse)
    if (logger && logger->file) {
        // Timestamp oluştur
        char timestamp[64];
        logger_get_timestamp(timestamp, sizeof(timestamp));
        
        // Log prefixini oluştur
        const char *type_str = (type == LOGGER_CLIENT) ? "CLIENT" : "SERVER";
        pid_t pid = getpid();
        
        // Log dosyasına yaz
        fprintf(logger->file, "[%s] [%s] [CONSOLE] [PID:%d] [SID:%s] ", 
                timestamp, type_str, pid, logger->session_id);
        
        va_start(args, format);
        vfprintf(logger->file, format, args);
        fflush(logger->file);
    }
    
    va_end(args);
}

/**
 * @brief Ortak kullanım için console çıktısını tüm aktif logger'lara yazar
 * @param format Printf-style format string
 * @param ... Değişken argümanlar
 * @details Çıktıyı console'a yazdırır ve aktif olan tüm logger'lara (client ve server)
 *          CONSOLE etiketi ile kaydeder. Ortak kullanılan modüller için idealdir.
 */
void logger_printf_common(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    // Console'a yazdır
    vprintf(format, args);
    fflush(stdout);
    
    // Timestamp oluştur
    char timestamp[64];
    logger_get_timestamp(timestamp, sizeof(timestamp));
    
    // Process ID'yi al
    pid_t pid = getpid();
    
    // Aktif olan tüm logger'lara yazdır
    if (client_logger && client_logger->file) {
        fprintf(client_logger->file, "[%s] [CLIENT] [CONSOLE] [PID:%d] [SID:%s] ", 
                timestamp, pid, client_logger->session_id);
        
        va_start(args, format);
        vfprintf(client_logger->file, format, args);
        fflush(client_logger->file);
    }
    
    if (server_logger && server_logger->file) {
        fprintf(server_logger->file, "[%s] [SERVER] [CONSOLE] [PID:%d] [SID:%s] ", 
                timestamp, pid, server_logger->session_id);
        
        va_start(args, format);
        vfprintf(server_logger->file, format, args);
        fflush(server_logger->file);
    }
    
    va_end(args);
}
