/**
 * @file load_balancer.h
 * @brief İstemci tarafı akıllı load balancer yöneticisi
 * @details Bu dosya, istemci uygulamasında sunucu seçimi ve yük dengeleme
 *          algoritmaları için gerekli yapıları ve fonksiyonları içerir.
 * @author Ali Burak Pekışık
 * @date 2025
 * @version 1.0
 */

#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Maksimum sunucu sayısı
 */
#define MAX_SERVERS 10

/**
 * @brief Sunucu sağlık kontrolü timeout süresi (saniye)
 */
#define HEALTH_CHECK_TIMEOUT 5

/**
 * @brief Sunucu istatistiklerini güncelleme aralığı (saniye)
 */
#define STATS_UPDATE_INTERVAL 30

/**
 * @brief Load balancer algoritmaları
 */
typedef enum {
    LB_ROUND_ROBIN,     ///< Sırayla dönüşümlü
    LB_LEAST_CONN,      ///< En az bağlantı
    LB_WEIGHTED_ROUND_ROBIN, ///< Ağırlıklı dönüşümlü
    LB_IP_HASH,         ///< IP hash tabanlı
    LB_LEAST_RESPONSE_TIME, ///< En az yanıt süresi
    LB_ADAPTIVE         ///< Uyarlamalı algoritma
} lb_algorithm_t;

/**
 * @brief Sunucu durumu
 */
typedef enum {
    SERVER_HEALTHY,     ///< Sunucu sağlıklı
    SERVER_UNHEALTHY,   ///< Sunucu sağlıksız
    SERVER_UNKNOWN,     ///< Sunucu durumu bilinmiyor
    SERVER_MAINTENANCE  ///< Sunucu bakımda
} server_status_t;

/**
 * @brief Sunucu bilgileri yapısı
 */
typedef struct {
    char host[256];             ///< Sunucu IP adresi veya hostname
    int tcp_port;               ///< TCP port numarası
    int udp_port;               ///< UDP port numarası
    int p2p_port;               ///< P2P port numarası
    int control_port;           ///< Kontrol port numarası
    int weight;                 ///< Sunucu ağırlığı (1-10)
    server_status_t status;     ///< Sunucu durumu
    
    // İstatistikler
    uint64_t total_requests;    ///< Toplam istek sayısı
    uint64_t failed_requests;   ///< Başarısız istek sayısı
    uint64_t active_connections; ///< Aktif bağlantı sayısı
    double avg_response_time;   ///< Ortalama yanıt süresi (ms)
    double cpu_usage;           ///< CPU kullanımı (%)
    double memory_usage;        ///< Bellek kullanımı (%)
    
    // Sağlık kontrol bilgileri
    time_t last_health_check;   ///< Son sağlık kontrolü zamanı
    int consecutive_failures;   ///< Ardışık başarısızlık sayısı
    bool is_backup;             ///< Yedek sunucu mu?
} server_info_t;

/**
 * @brief Load balancer konfigürasyonu
 */
typedef struct {
    lb_algorithm_t algorithm;           ///< Kullanılan algoritma
    server_info_t servers[MAX_SERVERS]; ///< Sunucu listesi
    int server_count;                   ///< Aktif sunucu sayısı
    int current_server_index;           ///< Mevcut sunucu indeksi (round robin için)
    bool health_check_enabled;          ///< Sağlık kontrolü aktif mi?
    int health_check_interval;          ///< Sağlık kontrolü aralığı (saniye)
    int max_failures;                   ///< Maksimum başarısızlık sayısı
    int connection_timeout;             ///< Bağlantı timeout süresi (saniye)
    bool sticky_sessions;               ///< Sticky session aktif mi?
    char session_id[64];                ///< Session ID (sticky session için)
    int assigned_server_index;          ///< Bu client için atanan sunucu indeksi (-1: atanmamış)
    bool session_established;           ///< Session kurulmuş mu?
} lb_config_t;

/**
 * @brief Sunucu seçimi sonucu
 */
typedef struct {
    server_info_t *server;      ///< Seçilen sunucu
    int server_index;           ///< Sunucu indeksi
    bool is_failover;           ///< Failover durumu mu?
    char reason[256];           ///< Seçim sebebi
} server_selection_result_t;

/**
 * @brief Load balancer başlatma
 * @param config Load balancer konfigürasyonu
 * @return 0 başarılı, -1 hata
 */
int lb_init(lb_config_t *config);

/**
 * @brief Load balancer temizleme
 * @param config Load balancer konfigürasyonu
 */
void lb_cleanup(lb_config_t *config);

/**
 * @brief Sunucu ekleme
 * @param config Load balancer konfigürasyonu
 * @param host Sunucu host adresi
 * @param tcp_port TCP port
 * @param udp_port UDP port
 * @param p2p_port P2P port
 * @param control_port Kontrol port
 * @param weight Sunucu ağırlığı
 * @param is_backup Yedek sunucu mu?
 * @return 0 başarılı, -1 hata
 */
int lb_add_server(lb_config_t *config, const char *host, 
                  int tcp_port, int udp_port, int p2p_port, int control_port,
                  int weight, bool is_backup);

/**
 * @brief En iyi sunucuyu seçme
 * @param config Load balancer konfigürasyonu
 * @param client_ip İstemci IP adresi (IP hash için)
 * @return Seçilen sunucu bilgisi
 */
server_selection_result_t lb_select_server(lb_config_t *config, const char *client_ip);

/**
 * @brief Sunucu sağlık kontrolü
 * @param server Kontrol edilecek sunucu
 * @return true sağlıklı, false sağlıksız
 */
bool lb_check_server_health(server_info_t *server);

/**
 * @brief Tüm sunucuların sağlık kontrolü
 * @param config Load balancer konfigürasyonu
 * @return Sağlıklı sunucu sayısı
 */
int lb_check_all_servers_health(lb_config_t *config);

/**
 * @brief Sunucu istatistiklerini güncelleme
 * @param server Güncellenecek sunucu
 * @param response_time Yanıt süresi (ms)
 * @param success Başarılı mı?
 */
void lb_update_server_stats(server_info_t *server, double response_time, bool success);

/**
 * @brief Load balancer istatistikleri yazdırma
 * @param config Load balancer konfigürasyonu
 */
void lb_print_stats(const lb_config_t *config);

/**
 * @brief En iyi algoritma seçimi (uyarlamalı)
 * @param config Load balancer konfigürasyonu
 * @return Önerilen algoritma
 */
lb_algorithm_t lb_choose_best_algorithm(const lb_config_t *config);

/**
 * @brief Sunucu çevrimdışı işaretleme
 * @param config Load balancer konfigürasyonu
 * @param server_index Sunucu indeksi
 */
void lb_mark_server_offline(lb_config_t *config, int server_index);

/**
 * @brief Sunucu çevrimiçi işaretleme
 * @param config Load balancer konfigürasyonu
 * @param server_index Sunucu indeksi
 */
void lb_mark_server_online(lb_config_t *config, int server_index);

/**
 * @brief Varsayılan konfigürasyon oluşturma
 * @return Varsayılan load balancer konfigürasyonu
 */
lb_config_t lb_create_default_config(void);

/**
 * @brief Config dosyasından sunucuları yükleme
 * @param config Load balancer konfigürasyonu
 * @param config_file Config dosyası yolu
 * @return 0 başarılı, -1 hata
 */
int lb_load_config_file(lb_config_t *config, const char *config_file);

/**
 * @brief Sticky session aktif etme
 * @param config Load balancer konfigürasyonu
 * @param enable True: aktif, False: devre dışı
 */
void lb_enable_sticky_sessions(lb_config_t *config, bool enable);

/**
 * @brief Sticky session kurma
 * @param config Load balancer konfigürasyonu
 * @param server_index Atanacak sunucu indeksi
 * @param session_id Session ID (opsiyonel)
 * @return 0 başarılı, -1 hata
 */
int lb_establish_sticky_session(lb_config_t *config, int server_index, const char *session_id);

/**
 * @brief Sticky session sonlandırma
 * @param config Load balancer konfigürasyonu
 */
void lb_end_sticky_session(lb_config_t *config);

/**
 * @brief Atanan sunucu bilgilerini alma
 * @param config Load balancer konfigürasyonu
 * @return Atanan sunucu bilgisi, NULL ise atanmamış
 */
server_info_t* lb_get_assigned_server(lb_config_t *config);

/**
 * @brief Session durumunu kontrol etme
 * @param config Load balancer konfigürasyonu
 * @return True: session aktif, False: session yok
 */
bool lb_is_session_active(lb_config_t *config);

#endif // LOAD_BALANCER_H
