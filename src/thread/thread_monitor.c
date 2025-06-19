#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/resource.h>
#include "thread_monitor.h"
#include "config.h"

static thread_info_t active_threads[CONFIG_MAX_CLIENTS];
static int thread_count = 0;
static int healthcheck_count = 0;
static int total_connections = 0;
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t server_start_time;

// Queue sistemi
static queue_client_t* queue_head = NULL;
static queue_client_t* queue_tail = NULL;
static int queue_size = 0;
static int total_queued = 0;
static int queue_processed = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_condition = PTHREAD_COND_INITIALIZER;

// Thread bilgilerini ekle
void add_thread_info(pthread_t thread_id, int client_socket, const char* client_ip, int client_port) {
    pthread_mutex_lock(&thread_mutex);
    
    for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {
        if (!active_threads[i].is_active) {
            active_threads[i].thread_id = thread_id;
            active_threads[i].client_socket = client_socket;
            active_threads[i].start_time = time(NULL);
            strncpy(active_threads[i].client_ip, client_ip, INET_ADDRSTRLEN);
            active_threads[i].client_port = client_port;
            active_threads[i].is_active = 1;
            snprintf(active_threads[i].thread_name, CONFIG_MAX_THREAD_NAME, 
                    "client_%s_%d", client_ip, client_port);
            thread_count++;
            break;
        }
    }
    
    pthread_mutex_unlock(&thread_mutex);
}

// Thread bilgilerini kaldır
void remove_thread_info(pthread_t thread_id) {
    pthread_mutex_lock(&thread_mutex);
    
    for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {
        if (active_threads[i].is_active && active_threads[i].thread_id == thread_id) {
            time_t duration = time(NULL) - active_threads[i].start_time;
            printf("Thread sonlandi: %s (Calisma suresi: %ld saniye)\n", 
                   active_threads[i].thread_name, duration);
            
            memset(&active_threads[i], 0, sizeof(thread_info_t));
            thread_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&thread_mutex);
}

// UDP packet için connection sayısını artır
void increment_udp_connection(void) {
    pthread_mutex_lock(&thread_mutex);
    total_connections++;
    pthread_mutex_unlock(&thread_mutex);
}

// Health check sayısını artır
void increment_healthcheck_count(void) {
    pthread_mutex_lock(&thread_mutex);
    healthcheck_count++;
    pthread_mutex_unlock(&thread_mutex);
}

// Health check sayısını al
int get_healthcheck_count(void) {
    pthread_mutex_lock(&thread_mutex);
    int count = healthcheck_count;
    pthread_mutex_unlock(&thread_mutex);
    return count;
}

// Toplam bağlantı sayacını artır
void increment_total_connections(void) {
    pthread_mutex_lock(&thread_mutex);
    total_connections++;
    pthread_mutex_unlock(&thread_mutex);
}

// Aktif thread sayısını al
int get_active_thread_count(void) {
    pthread_mutex_lock(&thread_mutex);
    int count = thread_count;
    pthread_mutex_unlock(&thread_mutex);
    return count;
}

// Toplam bağlantı sayısını al
int get_total_connections(void) {
    pthread_mutex_lock(&thread_mutex);
    int count = total_connections;
    pthread_mutex_unlock(&thread_mutex);
    return count;
}

// Thread istatistiklerini logla
void log_thread_stats(void) {
    pthread_mutex_lock(&thread_mutex);
    
    time_t current_time = time(NULL);
    time_t uptime = current_time - server_start_time;
    
    printf("\n=== THREAD & QUEUE ISTATISTIKLERI ===\n");
    printf("Server uptime: %ld saniye (%ld dakika)\n", uptime, uptime/60);
    printf("Aktif thread sayisi: %d/%d\n", thread_count, CONFIG_MAX_CLIENTS);
    printf("Queue boyutu: %d/%d\n", get_queue_size(), CONFIG_MAX_QUEUE_SIZE);
    printf("Toplam baglanti: %d\n", total_connections);
    printf("Health check sayisi: %d\n", healthcheck_count);
    printf("Aktif TCP client: %d\n", thread_count); // Gerçek client = aktif thread sayısı
    
    if (thread_count > 0) {
        printf("Aktif thread'ler:\n");
        for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {
            if (active_threads[i].is_active) {
                time_t duration = current_time - active_threads[i].start_time;
                printf("  - %s (Socket: %d, Sure: %ld s)\n", 
                       active_threads[i].thread_name,
                       active_threads[i].client_socket,
                       duration);
            }
        }
    } else {
        printf("Aktif thread yok\n");
    }
    
    // Sistem kaynak kullanımı
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("Bellek kullanimi: %ld KB\n", usage.ru_maxrss);
        printf("CPU zamanı: %ld.%06ld saniye\n", 
               usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
    }
    
    printf("====================================\n");
    
    pthread_mutex_unlock(&thread_mutex);
    
    // Queue istatistiklerini de göster
    if (get_queue_size() > 0) {
        log_queue_stats();
    }
    
    printf("\n");
    fflush(stdout);
}

// Thread monitoring sistemini başlat
void init_thread_monitoring(void) {
    server_start_time = time(NULL);
    memset(active_threads, 0, sizeof(active_threads));
    thread_count = 0;
    printf("Thread monitoring sistemi aktif\n");
    fflush(stdout);
}

// Thread monitor fonksiyonu
void* thread_monitor(void* arg) {
    (void)arg; // unused parameter warning'i önlemek için
    while (1) {
        sleep(CONFIG_THREAD_LOG_INTERVAL);
        log_thread_stats();
    }
    return NULL;
}

// Client'ı queue'ya ekle
void add_to_queue(int client_socket, struct sockaddr_in client_addr) {
    pthread_mutex_lock(&queue_mutex);
    
    // Queue full kontrolü
    if (queue_size >= CONFIG_MAX_QUEUE_SIZE) {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Queue dolu! Client reddediliyor: %s:%d\n", 
               client_ip, ntohs(client_addr.sin_port));
        
        const char* reject_msg = "QUEUE_FULL: Server kuyruğu dolu, lütfen daha sonra tekrar deneyin\n";
        send(client_socket, reject_msg, strlen(reject_msg), 0);
        close(client_socket);
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    
    // Yeni queue node oluştur
    queue_client_t* new_client = malloc(sizeof(queue_client_t));
    if (new_client == NULL) {
        printf("Queue memory allocation hatası!\n");
        close(client_socket);
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    
    new_client->client_socket = client_socket;
    new_client->client_addr = client_addr;
    new_client->queue_time = time(NULL);
    new_client->next = NULL;
    
    // Queue'ya ekle
    if (queue_tail == NULL) {
        queue_head = queue_tail = new_client;
    } else {
        queue_tail->next = new_client;
        queue_tail = new_client;
    }
    
    queue_size++;
    total_queued++;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Client queue'ya eklendi: %s:%d (Queue boyutu: %d/%d)\n", 
           client_ip, ntohs(client_addr.sin_port), queue_size, CONFIG_MAX_QUEUE_SIZE);
    
    // Queue işleyicisine signal gönder
    pthread_cond_signal(&queue_condition);
    
    pthread_mutex_unlock(&queue_mutex);
}

// Queue'dan client işle
int process_queue(void) {
    pthread_mutex_lock(&queue_mutex);
    
    if (queue_head == NULL) {
        pthread_mutex_unlock(&queue_mutex);
        return 0; // Queue boş
    }
    
    // İlk client'ı al
    queue_client_t* client = queue_head;
    queue_head = client->next;
    
    if (queue_head == NULL) {
        queue_tail = NULL;
    }
    
    queue_size--;
    queue_processed++;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    time_t wait_time = time(NULL) - client->queue_time;
    
    printf("Queue'dan client işleniyor: %s:%d (Bekleme süresi: %ld saniye)\n", 
           client_ip, ntohs(client->client_addr.sin_port), wait_time);
    
    int client_socket = client->client_socket;
    struct sockaddr_in client_addr = client->client_addr;
    
    free(client);
    pthread_mutex_unlock(&queue_mutex);
    
    // Client'ı işlemek için thread oluştur
    pthread_t thread_id;
    int *client_socket_ptr = malloc(sizeof(int));
    *client_socket_ptr = client_socket;
    
    if (pthread_create(&thread_id, NULL, (void* (*)(void*))handle_client, client_socket_ptr) != 0) {
        printf("Queue'dan thread oluşturma hatası!\n");
        free(client_socket_ptr);
        close(client_socket);
        return 0;
    }
    
    // Thread bilgilerini kaydet
    add_thread_info(thread_id, client_socket, client_ip, ntohs(client_addr.sin_port));
    pthread_detach(thread_id);
    
    printf("Queue'dan thread oluşturuldu (Thread ID: %lu)\n", thread_id);
    
    return 1; // Başarıyla işlendi
}

// Queue boyutunu al
int get_queue_size(void) {
    pthread_mutex_lock(&queue_mutex);
    int size = queue_size;
    pthread_mutex_unlock(&queue_mutex);
    return size;
}

// Queue istatistiklerini logla
void log_queue_stats(void) {
    pthread_mutex_lock(&queue_mutex);
    
    printf("=== QUEUE ISTATISTIKLERI ===\n");
    printf("Mevcut queue boyutu: %d/%d\n", queue_size, CONFIG_MAX_QUEUE_SIZE);
    printf("Toplam kuyruklanmış: %d\n", total_queued);
    printf("Toplam işlenmiş: %d\n", queue_processed);
    
    if (queue_size > 0) {
        printf("Bekleyen client'ler:\n");
        queue_client_t* current = queue_head;
        int index = 1;
        time_t current_time = time(NULL);
        
        while (current != NULL) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &current->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            time_t wait_time = current_time - current->queue_time;
            
            printf("  %d. %s:%d (Bekleme: %ld saniye)\n", 
                   index++, client_ip, ntohs(current->client_addr.sin_port), wait_time);
            
            current = current->next;
        }
    }
    
    printf("===========================\n");
    
    pthread_mutex_unlock(&queue_mutex);
}

// Queue'yu temizle
void clear_queue(void) {
    pthread_mutex_lock(&queue_mutex);
    
    queue_client_t* current = queue_head;
    while (current != NULL) {
        queue_client_t* next = current->next;
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Queue temizleme: %s:%d bağlantısı kapatılıyor\n", 
               client_ip, ntohs(current->client_addr.sin_port));
        
        close(current->client_socket);
        free(current);
        current = next;
    }
    
    queue_head = queue_tail = NULL;
    queue_size = 0;
    
    pthread_mutex_unlock(&queue_mutex);
}