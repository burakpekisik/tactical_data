/**
 * @file load_balancer.c
 * @brief İstemci tarafı akıllı load balancer implementasyonu
 * @details Bu dosya, istemci uygulamasında sunucu seçimi ve yük dengeleme
 *          algoritmaları için gerekli fonksiyonları implementa eder.
 * @author Ali Burak Pekışık
 * @date 2025
 * @version 1.0
 */

#include "load_balancer.h"
#include "logger.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <fcntl.h>

// Hash fonksiyonu için basit string hash
static uint32_t hash_string(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Sunucu bağlantısı test etme
static bool test_server_connection(const char *host, int port, int timeout) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct timeval tv;
    fd_set writefds;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Non-blocking socket yapma
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return false;
    }
    
    int result = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (result < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return false;
    }
    
    // Timeout ile bekleme
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);
    
    result = select(sockfd + 1, NULL, &writefds, NULL, &tv);
    close(sockfd);
    
    return (result > 0 && FD_ISSET(sockfd, &writefds));
}

// Zaman farkı hesaplama (milisaniye)
static double time_diff_ms(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
}

int lb_init(lb_config_t *config) {
    if (!config) {
        LOG_CLIENT_ERROR("Load balancer config is NULL");
        return -1;
    }
    
    memset(config, 0, sizeof(lb_config_t));
    config->algorithm = LB_IP_HASH;  // IP hash ile process'e göre farklı sunucu seçimi
    config->health_check_enabled = true;
    config->health_check_interval = 30;
    config->max_failures = 3;
    config->connection_timeout = 5;
    config->sticky_sessions = true;  // Sticky session varsayılan olarak aktif
    config->assigned_server_index = -1;  // Henüz atanmamış
    config->session_established = false;  // Session henüz kurulmamış
    
    LOG_CLIENT_INFO("Load balancer initialized successfully");
    return 0;
}

void lb_cleanup(lb_config_t *config) {
    if (!config) return;
    
    LOG_CLIENT_INFO("Load balancer cleanup completed");
}

int lb_add_server(lb_config_t *config, const char *host, 
                  int tcp_port, int udp_port, int p2p_port, int control_port,
                  int weight, bool is_backup) {
    if (!config || !host || config->server_count >= MAX_SERVERS) {
        LOG_CLIENT_ERROR("Cannot add server: invalid parameters or max servers reached");
        return -1;
    }
    
    server_info_t *server = &config->servers[config->server_count];
    
    strncpy(server->host, host, sizeof(server->host) - 1);
    server->host[sizeof(server->host) - 1] = '\0';
    server->tcp_port = tcp_port;
    server->udp_port = udp_port;
    server->p2p_port = p2p_port;
    server->control_port = control_port;
    server->weight = weight;
    server->status = SERVER_UNKNOWN;
    server->is_backup = is_backup;
    server->last_health_check = 0;
    server->consecutive_failures = 0;
    
    config->server_count++;
    
    LOG_CLIENT_INFO("Added server: %s:%d (weight: %d, backup: %s)", 
                    host, tcp_port, weight, is_backup ? "yes" : "no");
    return 0;
}

static server_selection_result_t select_round_robin(lb_config_t *config) {
    server_selection_result_t result = {0};
    
    // Process ID ve timestamp tabanlı hash ile farklı başlangıç noktaları
    static bool initialized = false;
    if (!initialized) {
        pid_t pid = getpid();
        time_t now = time(NULL);
        uint32_t hash = hash_string((char*)&pid) ^ hash_string((char*)&now);
        config->current_server_index = hash % config->server_count;
        initialized = true;
        LOG_CLIENT_INFO("Round robin initialized with starting index: %d (PID: %d)", 
                       config->current_server_index, pid);
    }
    
    int attempts = 0;
    while (attempts < config->server_count) {
        int index = config->current_server_index;
        server_info_t *server = &config->servers[index];
        
        config->current_server_index = (config->current_server_index + 1) % config->server_count;
        
        if (server->status == SERVER_HEALTHY || server->status == SERVER_UNKNOWN) {
            result.server = server;
            result.server_index = index;
            result.is_failover = false;
            int n = snprintf(result.reason, sizeof(result.reason), "Round robin selection (PID: %d)", getpid());
            if (n < 0 || n >= (int)sizeof(result.reason)) {
                strncpy(result.reason + sizeof(result.reason) - 5, "...", 4);
                result.reason[sizeof(result.reason) - 1] = '\0';
            }
            return result;
        }
        
        attempts++;
    }
    
    // Yedek sunucu seçimi
    for (int i = 0; i < config->server_count; i++) {
        if (config->servers[i].is_backup && config->servers[i].status != SERVER_UNHEALTHY) {
            result.server = &config->servers[i];
            result.server_index = i;
            result.is_failover = true;
            snprintf(result.reason, sizeof(result.reason), "Failover to backup server");
            return result;
        }
    }
    
    LOG_CLIENT_ERROR("No healthy servers available for round robin");
    return result;
}

static server_selection_result_t select_least_conn(lb_config_t *config) {
    server_selection_result_t result = {0};
    server_info_t *best_server = NULL;
    int best_index = -1;
    uint64_t min_connections = UINT64_MAX;
    
    for (int i = 0; i < config->server_count; i++) {
        server_info_t *server = &config->servers[i];
        
        if (server->status == SERVER_HEALTHY || server->status == SERVER_UNKNOWN) {
            if (server->active_connections < min_connections) {
                min_connections = server->active_connections;
                best_server = server;
                best_index = i;
            }
        }
    }
    
    if (best_server) {
        result.server = best_server;
        result.server_index = best_index;
        result.is_failover = false;
        int n = snprintf(result.reason, sizeof(result.reason), "Least connections: %lu", min_connections);
        if (n < 0 || n >= (int)sizeof(result.reason)) {
            strncpy(result.reason + sizeof(result.reason) - 5, "...", 4);
            result.reason[sizeof(result.reason) - 1] = '\0';
        }
        return result;
    }
    
    // Yedek sunucu seçimi
    for (int i = 0; i < config->server_count; i++) {
        if (config->servers[i].is_backup && config->servers[i].status != SERVER_UNHEALTHY) {
            result.server = &config->servers[i];
            result.server_index = i;
            result.is_failover = true;
            snprintf(result.reason, sizeof(result.reason), "Failover to backup server");
            return result;
        }
    }
    
    LOG_CLIENT_ERROR("No healthy servers available for least connections");
    return result;
}

static server_selection_result_t select_weighted_round_robin(lb_config_t *config) {
    server_selection_result_t result = {0};
    static int current_weights[MAX_SERVERS] = {0};
    static int total_weight = 0;
    
    // İlk çalıştırma için ağırlıkları hesapla
    if (total_weight == 0) {
        for (int i = 0; i < config->server_count; i++) {
            total_weight += config->servers[i].weight;
        }
    }
    
    int best_index = -1;
    int max_current_weight = -1;
    
    for (int i = 0; i < config->server_count; i++) {
        server_info_t *server = &config->servers[i];
        
        if (server->status == SERVER_HEALTHY || server->status == SERVER_UNKNOWN) {
            current_weights[i] += server->weight;
            
            if (current_weights[i] > max_current_weight) {
                max_current_weight = current_weights[i];
                best_index = i;
            }
        }
    }
    
    if (best_index >= 0) {
        current_weights[best_index] -= total_weight;
        result.server = &config->servers[best_index];
        result.server_index = best_index;
        result.is_failover = false;
        int n = snprintf(result.reason, sizeof(result.reason), "Weighted round robin (weight: %d)", config->servers[best_index].weight);
        if (n < 0 || n >= (int)sizeof(result.reason)) {
            strncpy(result.reason + sizeof(result.reason) - 5, "...", 4);
            result.reason[sizeof(result.reason) - 1] = '\0';
        }
        return result;
    }
    
    LOG_CLIENT_ERROR("No healthy servers available for weighted round robin");
    return result;
}

static server_selection_result_t select_ip_hash(lb_config_t *config, const char *client_ip) {
    server_selection_result_t result = {0};
    
    if (!client_ip) {
        client_ip = "127.0.0.1"; // Varsayılan IP
    }
    
    // Process ID ve timestamp ile unique hash oluştur
    pid_t pid = getpid();
    time_t now = time(NULL);
    char unique_str[256];
    snprintf(unique_str, sizeof(unique_str), "%s_%d_%ld", client_ip, pid, now);
    
    uint32_t hash = hash_string(unique_str);
    int index = hash % config->server_count;
    
    LOG_CLIENT_DEBUG("Process-based hash: pid=%d, time=%ld, hash=%u, index=%d", 
                     pid, now, hash, index);
    
    // Seçilen sunucu sağlıklı değilse, sonraki sağlıklı sunucuyu bul
    for (int i = 0; i < config->server_count; i++) {
        int current_index = (index + i) % config->server_count;
        server_info_t *server = &config->servers[current_index];
        
        if (server->status == SERVER_HEALTHY || server->status == SERVER_UNKNOWN) {
            result.server = server;
            result.server_index = current_index;
            result.is_failover = (i > 0);
            snprintf(result.reason, sizeof(result.reason), 
                    "Process hash for PID:%d (hash: %u)", pid, hash);
            return result;
        }
    }
    
    LOG_CLIENT_ERROR("No healthy servers available for process hash");
    return result;
}

static server_selection_result_t select_least_response_time(lb_config_t *config) {
    server_selection_result_t result = {0};
    server_info_t *best_server = NULL;
    int best_index = -1;
    double min_response_time = INFINITY;
    
    for (int i = 0; i < config->server_count; i++) {
        server_info_t *server = &config->servers[i];
        
        if (server->status == SERVER_HEALTHY || server->status == SERVER_UNKNOWN) {
            double response_time = server->avg_response_time;
            if (response_time == 0) response_time = 1.0; // Varsayılan değer
            
            if (response_time < min_response_time) {
                min_response_time = response_time;
                best_server = server;
                best_index = i;
            }
        }
    }
    
    if (best_server) {
        result.server = best_server;
        result.server_index = best_index;
        result.is_failover = false;
        int n = snprintf(result.reason, sizeof(result.reason), "Least response time: %.2f ms", min_response_time);
        if (n < 0 || n >= (int)sizeof(result.reason)) {
            strncpy(result.reason + sizeof(result.reason) - 5, "...", 4);
            result.reason[sizeof(result.reason) - 1] = '\0';
        }
        return result;
    }
    
    LOG_CLIENT_ERROR("No healthy servers available for least response time");
    return result;
}

lb_algorithm_t lb_choose_best_algorithm(const lb_config_t *config) {
    if (!config || config->server_count == 0) {
        return LB_ROUND_ROBIN;
    }
    
    // Sunucu sayısına göre algoritma seçimi
    if (config->server_count == 1) {
        return LB_ROUND_ROBIN;
    }
    
    // CPU ve bellek kullanım ortalaması
    double avg_cpu = 0, avg_memory = 0;
    int healthy_servers = 0;
    
    for (int i = 0; i < config->server_count; i++) {
        const server_info_t *server = &config->servers[i];
        if (server->status == SERVER_HEALTHY) {
            avg_cpu += server->cpu_usage;
            avg_memory += server->memory_usage;
            healthy_servers++;
        }
    }
    
    if (healthy_servers == 0) {
        return LB_ROUND_ROBIN;
    }
    
    avg_cpu /= healthy_servers;
    avg_memory /= healthy_servers;
    
    // Yük yoğunluğuna göre algoritma seçimi
    if (avg_cpu > 80 || avg_memory > 80) {
        return LB_LEAST_CONN; // Yoğun durumda en az bağlantı
    } else if (avg_cpu > 60 || avg_memory > 60) {
        return LB_LEAST_RESPONSE_TIME; // Orta yoğunlukta yanıt süresi
    } else {
        return LB_WEIGHTED_ROUND_ROBIN; // Normal durumda ağırlıklı
    }
}

server_selection_result_t lb_select_server(lb_config_t *config, const char *client_ip) {
    server_selection_result_t result = {0};
    
    if (!config || config->server_count == 0) {
        LOG_CLIENT_ERROR("Load balancer not configured or no servers available");
        return result;
    }
    
    // Sticky session kontrolü - eğer aktif ve daha önce bir sunucu atanmışsa
    if (config->sticky_sessions && config->session_established && 
        config->assigned_server_index >= 0 && config->assigned_server_index < config->server_count) {
        
        server_info_t *assigned_server = &config->servers[config->assigned_server_index];
        
        // Atanan sunucu sağlıklı mı kontrol et
        if (assigned_server->status == SERVER_HEALTHY || assigned_server->status == SERVER_UNKNOWN) {
            result.server = assigned_server;
            result.server_index = config->assigned_server_index;
            result.is_failover = false;
            int n = snprintf(result.reason, sizeof(result.reason), "Sticky session to server %d (%s:%d)", config->assigned_server_index, assigned_server->host, assigned_server->tcp_port);
            if (n < 0 || n >= (int)sizeof(result.reason)) {
                strncpy(result.reason + sizeof(result.reason) - 5, "...", 4);
                result.reason[sizeof(result.reason) - 1] = '\0';
            }
            
            LOG_CLIENT_INFO("Using sticky session: server %d (%s:%d)", 
                           config->assigned_server_index, assigned_server->host, assigned_server->tcp_port);
            return result;
        } else {
            LOG_CLIENT_WARN("Assigned server %d is unhealthy, selecting new server", 
                           config->assigned_server_index);
            config->assigned_server_index = -1;
            config->session_established = false;
        }
    }
    
    // Sağlık kontrolü
    if (config->health_check_enabled) {
        time_t now = time(NULL);
        if (now - config->servers[0].last_health_check > config->health_check_interval) {
            lb_check_all_servers_health(config);
        }
    }
    
    // Uyarlamalı algoritma seçimi
    lb_algorithm_t algorithm = config->algorithm;
    if (algorithm == LB_ADAPTIVE) {
        algorithm = lb_choose_best_algorithm(config);
    }
    
    // Algoritma seçimi
    switch (algorithm) {
        case LB_ROUND_ROBIN:
            result = select_round_robin(config);
            break;
        case LB_LEAST_CONN:
            result = select_least_conn(config);
            break;
        case LB_WEIGHTED_ROUND_ROBIN:
            result = select_weighted_round_robin(config);
            break;
        case LB_IP_HASH:
            result = select_ip_hash(config, client_ip);
            break;
        case LB_LEAST_RESPONSE_TIME:
            result = select_least_response_time(config);
            break;
        default:
            result = select_round_robin(config);
            break;
    }
    
    if (result.server) {
        result.server->active_connections++;
        LOG_CLIENT_DEBUG("Selected server: %s:%d (%s)", 
                        result.server->host, result.server->tcp_port, result.reason);
        
        // Sticky session aktif ve henüz session kurulmamışsa, yeni sunucu için session kur
        if (config->sticky_sessions && !config->session_established) {
            lb_establish_sticky_session(config, result.server_index, NULL);
        }
    }
    
    return result;
}

bool lb_check_server_health(server_info_t *server) {
    if (!server) return false;
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Control port ile sağlık kontrolü
    bool is_healthy = test_server_connection(server->host, server->control_port, 
                                            HEALTH_CHECK_TIMEOUT);
    
    gettimeofday(&end, NULL);
    double response_time = time_diff_ms(start, end);
    
    server->last_health_check = time(NULL);
    
    if (is_healthy) {
        server->status = SERVER_HEALTHY;
        server->consecutive_failures = 0;
        server->avg_response_time = (server->avg_response_time + response_time) / 2.0;
        LOG_CLIENT_DEBUG("Server %s:%d is healthy (response: %.2f ms)", 
                        server->host, server->control_port, response_time);
    } else {
        server->consecutive_failures++;
        if (server->consecutive_failures >= 3) {
            server->status = SERVER_UNHEALTHY;
            LOG_CLIENT_WARN("Server %s:%d marked as unhealthy (failures: %d)", 
                              server->host, server->control_port, server->consecutive_failures);
        }
    }
    
    return is_healthy;
}

int lb_check_all_servers_health(lb_config_t *config) {
    if (!config) return 0;
    
    int healthy_count = 0;
    
    for (int i = 0; i < config->server_count; i++) {
        if (lb_check_server_health(&config->servers[i])) {
            healthy_count++;
        }
    }
    
    LOG_CLIENT_INFO("Health check completed: %d/%d servers healthy", 
                    healthy_count, config->server_count);
    return healthy_count;
}

void lb_update_server_stats(server_info_t *server, double response_time, bool success) {
    if (!server) return;
    
    server->total_requests++;
    if (!success) {
        server->failed_requests++;
    }
    
    if (response_time > 0) {
        if (server->avg_response_time == 0) {
            server->avg_response_time = response_time;
        } else {
            server->avg_response_time = (server->avg_response_time * 0.8) + (response_time * 0.2);
        }
    }
    
    if (server->active_connections > 0) {
        server->active_connections--;
    }
}

void lb_print_stats(const lb_config_t *config) {
    if (!config) return;
    
    printf("\n=== Load Balancer Statistics ===\n");
    printf("Algorithm: %s\n", 
           config->algorithm == LB_ROUND_ROBIN ? "Round Robin" :
           config->algorithm == LB_LEAST_CONN ? "Least Connections" :
           config->algorithm == LB_WEIGHTED_ROUND_ROBIN ? "Weighted Round Robin" :
           config->algorithm == LB_IP_HASH ? "IP Hash" :
           config->algorithm == LB_LEAST_RESPONSE_TIME ? "Least Response Time" :
           config->algorithm == LB_ADAPTIVE ? "Adaptive" : "Unknown");
    
    printf("Total Servers: %d\n", config->server_count);
    printf("Health Check: %s\n", config->health_check_enabled ? "Enabled" : "Disabled");
    
    printf("\nServer Details:\n");
    for (int i = 0; i < config->server_count; i++) {
        const server_info_t *server = &config->servers[i];
        printf("  Server %d: %s:%d\n", i+1, server->host, server->tcp_port);
        printf("    Status: %s\n", 
               server->status == SERVER_HEALTHY ? "Healthy" :
               server->status == SERVER_UNHEALTHY ? "Unhealthy" :
               server->status == SERVER_MAINTENANCE ? "Maintenance" : "Unknown");
        printf("    Weight: %d\n", server->weight);
        printf("    Requests: %lu (failed: %lu)\n", 
               server->total_requests, server->failed_requests);
        printf("    Active Connections: %lu\n", server->active_connections);
        printf("    Avg Response Time: %.2f ms\n", server->avg_response_time);
        printf("    Consecutive Failures: %d\n", server->consecutive_failures);
        printf("    Backup: %s\n", server->is_backup ? "Yes" : "No");
        printf("\n");
    }
}

void lb_mark_server_offline(lb_config_t *config, int server_index) {
    if (!config || server_index < 0 || server_index >= config->server_count) return;
    
    config->servers[server_index].status = SERVER_MAINTENANCE;
    LOG_CLIENT_INFO("Server %s:%d marked as offline", 
                    config->servers[server_index].host, 
                    config->servers[server_index].tcp_port);
}

void lb_mark_server_online(lb_config_t *config, int server_index) {
    if (!config || server_index < 0 || server_index >= config->server_count) return;
    
    config->servers[server_index].status = SERVER_HEALTHY;
    config->servers[server_index].consecutive_failures = 0;
    LOG_CLIENT_INFO("Server %s:%d marked as online", 
                    config->servers[server_index].host, 
                    config->servers[server_index].tcp_port);
}

lb_config_t lb_create_default_config(void) {
    lb_config_t config = {0};
    
    config.algorithm = LB_IP_HASH;  // IP hash ile process'e göre farklı sunucu seçimi
    config.health_check_enabled = true;
    config.health_check_interval = 30;
    config.max_failures = 3;
    config.connection_timeout = 5;
    config.sticky_sessions = true;  // Sticky session varsayılan olarak aktif
    config.assigned_server_index = -1;  // Henüz atanmamış
    config.session_established = false;  // Session henüz kurulmamış
    
    // Varsayılan sunucuları ekle
    lb_add_server(&config, "127.0.0.1", 8080, 8081, 8082, 9090, 3, false);
    lb_add_server(&config, "127.0.0.1", 8083, 8084, 8085, 9091, 3, false);
    lb_add_server(&config, "127.0.0.1", 8086, 8087, 8088, 9092, 2, false);
    
    return config;
}

/**
 * @brief Config dosyasından sunucuları yükleme
 * @param config Load balancer konfigürasyonu
 * @param config_file Config dosyası yolu
 * @return 0 başarılı, -1 hata
 */
int lb_load_config_file(lb_config_t *config, const char *config_file) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        fprintf(stderr, "Config dosyası açılamadı: %s\n", config_file);
        return -1;
    }
    
    char line[512];
    int loaded_servers = 0;
    
    while (fgets(line, sizeof(line), file)) {
        // Boş satırları ve yorum satırlarını atla
        if (line[0] == '\n' || line[0] == '#') {
            continue;
        }
        
        // Satır sonundaki newline karakterini kaldır
        line[strcspn(line, "\n")] = 0;
        
        // Format: host:tcp_port:udp_port:p2p_port:control_port:weight:backup
        char host[256];
        int tcp_port, udp_port, p2p_port, control_port, weight;
        char backup_str[10];
        
        int parsed = sscanf(line, "%255[^:]:%d:%d:%d:%d:%d:%9s", 
                           host, &tcp_port, &udp_port, &p2p_port, 
                           &control_port, &weight, backup_str);
        
        if (parsed == 7) {
            bool is_backup = (strcmp(backup_str, "true") == 0);
            
            if (lb_add_server(config, host, tcp_port, udp_port, p2p_port, 
                             control_port, weight, is_backup) == 0) {
                loaded_servers++;
                printf("Sunucu yüklendi: %s:%d (ağırlık: %d, backup: %s)\n", 
                       host, tcp_port, weight, is_backup ? "evet" : "hayır");
            }
        } else {
            fprintf(stderr, "Geçersiz satır formatı: %s\n", line);
        }
    }
    
    fclose(file);
    printf("Toplam %d sunucu config dosyasından yüklendi.\n", loaded_servers);
    return 0;
}

/**
 * @brief Sticky session aktif etme
 * @param config Load balancer konfigürasyonu
 * @param enable True: aktif, False: devre dışı
 */
void lb_enable_sticky_sessions(lb_config_t *config, bool enable) {
    if (!config) return;
    
    config->sticky_sessions = enable;
    if (!enable) {
        // Sticky session devre dışı bırakılırsa, mevcut session'ı temizle
        config->assigned_server_index = -1;
        config->session_established = false;
        memset(config->session_id, 0, sizeof(config->session_id));
    }
    
    LOG_CLIENT_INFO("Sticky sessions %s", enable ? "enabled" : "disabled");
}

/**
 * @brief Sticky session kurma
 * @param config Load balancer konfigürasyonu
 * @param server_index Atanacak sunucu indeksi
 * @param session_id Session ID (opsiyonel)
 * @return 0 başarılı, -1 hata
 */
int lb_establish_sticky_session(lb_config_t *config, int server_index, const char *session_id) {
    if (!config || server_index < 0 || server_index >= config->server_count) {
        LOG_CLIENT_ERROR("Invalid config or server index for sticky session");
        return -1;
    }
    
    server_info_t *server = &config->servers[server_index];
    if (server->status == SERVER_UNHEALTHY) {
        LOG_CLIENT_ERROR("Cannot establish sticky session with unhealthy server %d", server_index);
        return -1;
    }
    
    config->assigned_server_index = server_index;
    config->session_established = true;
    
    // Session ID ayarla
    if (session_id) {
        strncpy(config->session_id, session_id, sizeof(config->session_id) - 1);
        config->session_id[sizeof(config->session_id) - 1] = '\0';
    } else {
        // Otomatik session ID oluştur
        snprintf(config->session_id, sizeof(config->session_id), 
                "session_%d_%ld", server_index, time(NULL));
    }
    
    LOG_CLIENT_INFO("Sticky session established: server %d (%s:%d), session_id: %s", 
                   server_index, server->host, server->tcp_port, config->session_id);
    
    return 0;
}

/**
 * @brief Sticky session sonlandırma
 * @param config Load balancer konfigürasyonu
 */
void lb_end_sticky_session(lb_config_t *config) {
    if (!config) return;
    
    if (config->session_established) {
        LOG_CLIENT_INFO("Ending sticky session: server %d, session_id: %s", 
                       config->assigned_server_index, config->session_id);
        
        config->assigned_server_index = -1;
        config->session_established = false;
        memset(config->session_id, 0, sizeof(config->session_id));
    }
}

/**
 * @brief Atanan sunucu bilgilerini alma
 * @param config Load balancer konfigürasyonu
 * @return Atanan sunucu bilgisi, NULL ise atanmamış
 */
server_info_t* lb_get_assigned_server(lb_config_t *config) {
    if (!config || !config->session_established || 
        config->assigned_server_index < 0 || config->assigned_server_index >= config->server_count) {
        return NULL;
    }
    
    return &config->servers[config->assigned_server_index];
}

/**
 * @brief Session durumunu kontrol etme
 * @param config Load balancer konfigürasyonu
 * @return True: session aktif, False: session yok
 */
bool lb_is_session_active(lb_config_t *config) {
    if (!config) return false;
    
    return config->sticky_sessions && config->session_established && 
           config->assigned_server_index >= 0 && config->assigned_server_index < config->server_count;
}
