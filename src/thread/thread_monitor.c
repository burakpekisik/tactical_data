/**
 * @file thread_monitor.c
 * @brief Thread izleme ve bağlantı queue yönetim sistemi
 * @ingroup thread_management
 * @author Taktik Veri Sistemi
 * @date 2025
 * 
 * Bu dosya çok threaded sunucu uygulaması için thread monitoring ve
 * client connection queue yönetim sistemini sağlar. Production ortamında
 * thread pool yönetimi, resource monitoring ve bağlantı kuyruğu işlemlerini içerir.
 * 
 * Ana özellikler:
 * - Aktif thread bilgilerini tracking
 * - Client connection queue yönetimi
 * - Thread yaşam döngüsü monitoring
 * - Sistem kaynak kullanım takibi
 * - Health check counter tracking
 * - Queue overflow kontrolü ve yönetimi
 * - Thread-safe operations (mutex protection)
 * 
 * Kullanılan veri yapıları:
 * - thread_info_t: Aktif thread bilgileri
 * - queue_client_t: Bekleyen client bağlantıları
 * - Global mutex'ler: Thread-safe erişim için
 * 
 * @note Bu sistem production sunucusunda critical performance monitoring sağlar.
 *       Thread leak detection ve resource optimization için gereklidir.
 * 
 * @warning Tüm fonksiyonlar thread-safe'dir ancak mutex deadlock'larına dikkat edin.
 *          Queue overflow durumunda client bağlantıları reddedilir.
 */

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
#include "logger.h"

/// @brief Aktif thread bilgilerini tutan static array - CONFIG_MAX_CLIENTS kadar
static thread_info_t active_threads[CONFIG_MAX_CLIENTS];

/// @brief Mevcut aktif thread sayısı
static int thread_count = 0;

/// @brief Health check request sayısı (Docker health check vb.)
static int healthcheck_count = 0;

/// @brief Toplam kabul edilen bağlantı sayısı (TCP + UDP)
static int total_connections = 0;

/// @brief Thread işlemlerini korumak için mutex
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

/// @brief Sunucu başlangıç zamanı - uptime hesabı için
static time_t server_start_time;

/// @brief Client connection queue başlangıcı (linked list)
static queue_client_t* queue_head = NULL;

/// @brief Client connection queue sonu (linked list)
static queue_client_t* queue_tail = NULL;

/// @brief Mevcut queue boyutu
static int queue_size = 0;

/// @brief Toplam kuyruklanmış client sayısı (istatistik)
static int total_queued = 0;

/// @brief Toplam işlenmiş queue client sayısı (istatistik)
static int queue_processed = 0;

/// @brief Queue işlemlerini korumak için mutex
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

/// @brief Queue işleyici thread'i uyandırmak için condition variable
static pthread_cond_t queue_condition = PTHREAD_COND_INITIALIZER;

/**
 * @brief Yeni thread bilgisini aktif thread listesine ekler
 * @ingroup thread_management
 * 
 * Bir client bağlantısı için yeni thread oluşturulduğunda bu fonksiyon
 * çağrılarak thread'in bilgileri tracking sistemine eklenir.
 * 
 * Kaydedilen bilgiler:
 * - Thread ID (pthread_t)
 * - Client socket file descriptor
 * - Client IP adresi
 * - Client port numarası
 * - Thread başlangıç zamanı
 * - Thread friendly name
 * 
 * @param thread_id Pthread thread ID'si
 * @param client_socket Client socket file descriptor
 * @param client_ip Client IP adresi string formatında
 * @param client_port Client port numarası
 * 
 * @note Fonksiyon thread-safe'dir, mutex koruması altında çalışır.
 *       Boş slot bulamazsa ekleme yapmaz (silent fail).
 * 
 * @warning CONFIG_MAX_CLIENTS sınırını aşan thread'ler takip edilmez.
 *          Thread name formatı: "client_IP_PORT"
 * 
 * @see remove_thread_info()
 * @see get_active_thread_count()
 * 
 * Örnek kullanım:
 * @code
 * pthread_t tid;
 * int client_sock = accept(server_sock, ...);
 * pthread_create(&tid, NULL, handle_client, &client_sock);
 * add_thread_info(tid, client_sock, "192.168.1.100", 12345);
 * @endcode
 */
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

/**
 * @brief Thread bilgisini aktif thread listesinden kaldırır ve istatistik çıkarır
 * @ingroup thread_management
 * 
 * Thread sonlandığında bu fonksiyon çağrılarak thread'in bilgileri
 * tracking sisteminden kaldırılır ve çalışma süresi istatistiği çıkarılır.
 * 
 * İşlem adımları:
 * 1. Thread ID ile aktif thread listesinde arama yapar
 * 2. Thread bulunursa çalışma süresini hesaplar
 * 3. Konsola sonlandırma mesajı yazdırır
 * 4. Thread bilgilerini temizler (memset)
 * 5. Aktif thread sayacını azaltır
 * 
 * @param thread_id Kaldırılacak thread'in pthread ID'si
 * 
 * @note Fonksiyon thread-safe'dir, mutex koruması altında çalışır.
 *       Thread bulunamazsa sessizce hiçbir şey yapmaz.
 * 
 * @warning Thread sonlandıktan sonra mutlaka çağrılmalıdır,
 *          aksi halde thread leak izleme sisteminde kalır.
 * 
 * @see add_thread_info()
 * @see get_active_thread_count()
 * 
 * Örnek çıktı:
 * @code
 * Thread sonlandi: client_192.168.1.100_12345 (Calisma suresi: 45 saniye)
 * @endcode
 * 
 * Kullanım örneği:
 * @code
 * void* client_handler(void* arg) {
 *     pthread_t current_thread = pthread_self();
 *     // ... client işlemleri ...
 *     remove_thread_info(current_thread);
 *     return NULL;
 * }
 * @endcode
 */
// Thread bilgilerini kaldır
void remove_thread_info(pthread_t thread_id) {
    pthread_mutex_lock(&thread_mutex);
    
    for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {
        if (active_threads[i].is_active && active_threads[i].thread_id == thread_id) {
            time_t duration = time(NULL) - active_threads[i].start_time;
            PRINTF_LOG("Thread sonlandi: %s (Calisma suresi: %ld saniye)\n", 
                   active_threads[i].thread_name, duration);
            
            memset(&active_threads[i], 0, sizeof(thread_info_t));
            thread_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&thread_mutex);
}

/**
 * @brief UDP paket bağlantı sayacını thread-safe olarak artırır
 * @ingroup thread_management
 * 
 * UDP paketleri thread oluşturmadığı için bu fonksiyon ile
 * UDP bağlantı istatistikleri takip edilir.
 * 
 * @note Thread-safe, total_connections sayacını artırır
 * @see get_total_connections()
 */
// UDP packet için connection sayısını artır
void increment_udp_connection(void) {
    pthread_mutex_lock(&thread_mutex);
    total_connections++;
    pthread_mutex_unlock(&thread_mutex);
}

/**
 * @brief Health check request sayacını thread-safe olarak artırır
 * @ingroup thread_management
 * 
 * Docker health check, load balancer probe gibi sistem
 * sağlık kontrolleri için sayaç artırımı yapar.
 * 
 * @note Thread-safe, healthcheck_count sayacını artırır
 * @see get_healthcheck_count()
 */
// Health check sayısını artır
void increment_healthcheck_count(void) {
    pthread_mutex_lock(&thread_mutex);
    healthcheck_count++;
    pthread_mutex_unlock(&thread_mutex);
}

/**
 * @brief Toplam health check sayısını thread-safe olarak getirir
 * @ingroup thread_management
 * 
 * @return Mevcut health check request sayısı
 * @note Thread-safe okuma işlemi
 * @see increment_healthcheck_count()
 */
// Health check sayısını al
int get_healthcheck_count(void) {
    pthread_mutex_lock(&thread_mutex);
    int count = healthcheck_count;
    pthread_mutex_unlock(&thread_mutex);
    return count;
}

/**
 * @brief Toplam bağlantı sayacını thread-safe olarak artırır
 * @ingroup thread_management
 * 
 * TCP client bağlantıları için genel sayaç artırımı yapar.
 * 
 * @note Thread-safe, total_connections sayacını artırır
 * @see get_total_connections()
 */
// Toplam bağlantı sayacını artır
void increment_total_connections(void) {
    pthread_mutex_lock(&thread_mutex);
    total_connections++;
    pthread_mutex_unlock(&thread_mutex);
}

/**
 * @brief Mevcut aktif thread sayısını thread-safe olarak getirir
 * @ingroup thread_management
 * 
 * Thread pool doluluk kontrolü için kullanılır.
 * 
 * @return Mevcut aktif TCP client thread sayısı
 * @note Thread-safe okuma işlemi
 * @see add_thread_info()
 * @see remove_thread_info()
 */
// Aktif thread sayısını al
int get_active_thread_count(void) {
    pthread_mutex_lock(&thread_mutex);
    int count = thread_count;
    pthread_mutex_unlock(&thread_mutex);
    return count;
}

/**
 * @brief Toplam kabul edilen bağlantı sayısını thread-safe olarak getirir
 * @ingroup thread_management
 * 
 * TCP + UDP toplam bağlantı istatistiği sağlar.
 * 
 * @return Toplam bağlantı sayısı (TCP + UDP)
 * @note Thread-safe okuma işlemi
 * @see increment_total_connections()
 * @see increment_udp_connection()
 */
// Toplam bağlantı sayısını al
int get_total_connections(void) {
    pthread_mutex_lock(&thread_mutex);
    int count = total_connections;
    pthread_mutex_unlock(&thread_mutex);
    return count;
}

/**
 * @brief Kapsamlı thread ve sistem istatistiklerini konsola yazdırır
 * @ingroup thread_management
 * 
 * Bu fonksiyon sunucu durumu hakkında detaylı bilgileri konsola yazdırır.
 * Production monitoring ve debugging için kritik bilgiler sağlar.
 * 
 * Gösterilen istatistikler:
 * - Server uptime (saniye ve dakika cinsinden)
 * - Aktif thread sayısı ve maksimum limit
 * - Queue boyutu ve maksimum kapasitesi
 * - Toplam bağlantı sayısı (TCP + UDP)
 * - Health check request sayısı
 * - Her aktif thread'in detaylı bilgileri
 * - Sistem kaynak kullanımı (RAM, CPU)
 * 
 * Aktif thread detayları:
 * - Thread friendly name
 * - Socket file descriptor
 * - Çalışma süresi (saniye)
 * 
 * Sistem kaynakları:
 * - Maksimum bellek kullanımı (KB)
 * - CPU zamanı (kullanıcı modu)
 * 
 * @note Fonksiyon thread-safe'dir, mutex koruması altında çalışır.
 *       Queue size > 0 ise ayrıca queue istatistiklerini de gösterir.
 * 
 * @warning getrusage() çağrısı Linux/Unix sistemlerde çalışır.
 *          Windows portability için ek kodlama gerekebilir.
 * 
 * @see log_queue_stats()
 * @see init_thread_monitoring()
 * 
 * Örnek çıktı:
 * @code
 * === THREAD & QUEUE ISTATISTIKLERI ===
 * Server uptime: 3600 saniye (60 dakika)
 * Aktif thread sayisi: 5/10
 * Queue boyutu: 2/50
 * Toplam baglanti: 127
 * Health check sayisi: 15
 * Aktif TCP client: 5
 * Aktif thread'ler:
 *   - client_192.168.1.100_12345 (Socket: 8, Sure: 120 s)
 *   - client_192.168.1.101_23456 (Socket: 9, Sure: 45 s)
 * Bellek kullanimi: 2048 KB
 * CPU zamanı: 12.345678 saniye
 * ====================================
 * @endcode
 */
// Thread istatistiklerini logla
void log_thread_stats(void) {
    pthread_mutex_lock(&thread_mutex);
    
    time_t current_time = time(NULL);
    time_t uptime = current_time - server_start_time;
    
    PRINTF_LOG("\n=== THREAD & QUEUE ISTATISTIKLERI ===\n");
    PRINTF_LOG("Server uptime: %ld saniye (%ld dakika)\n", uptime, uptime/60);
    PRINTF_LOG("Aktif thread sayisi: %d/%d\n", thread_count, CONFIG_MAX_CLIENTS);
    PRINTF_LOG("Queue boyutu: %d/%d\n", get_queue_size(), CONFIG_MAX_QUEUE_SIZE);
    PRINTF_LOG("Toplam baglanti: %d\n", total_connections);
    PRINTF_LOG("Health check sayisi: %d\n", healthcheck_count);
    PRINTF_LOG("Aktif TCP client: %d\n", thread_count); // Gerçek client = aktif thread sayısı
    
    if (thread_count > 0) {
        PRINTF_LOG("Aktif thread'ler:\n");
        for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {
            if (active_threads[i].is_active) {
                time_t duration = current_time - active_threads[i].start_time;
                PRINTF_LOG("  - %s (Socket: %d, Sure: %ld s)\n", 
                       active_threads[i].thread_name,
                       active_threads[i].client_socket,
                       duration);
            }
        }
    } else {
        PRINTF_LOG("Aktif thread yok\n");
    }
    
    // Sistem kaynak kullanımı
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        PRINTF_LOG("Bellek kullanimi: %ld KB\n", usage.ru_maxrss);
        PRINTF_LOG("CPU zamanı: %ld.%06ld saniye\n", 
               usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
    }
    
    PRINTF_LOG("====================================\n");
    
    pthread_mutex_unlock(&thread_mutex);
    
    // Queue istatistiklerini de göster
    if (get_queue_size() > 0) {
        log_queue_stats();
    }
    
    PRINTF_LOG("\n");
    fflush(stdout);
}

/**
 * @brief Thread monitoring sistemini başlatır ve global değişkenleri ilklendirir
 * @ingroup thread_management
 * 
 * Sunucu başlangıcında çağrılan bu fonksiyon thread tracking sistemini hazırlar.
 * Tüm global değişkenleri ve veri yapılarını temiz bir duruma getirir.
 * 
 * İlklendirilen değişkenler:
 * - server_start_time: Mevcut zaman
 * - active_threads: Sıfırlanmış array
 * - thread_count: 0
 * - Queue ve istatistik değişkenleri
 * 
 * @note Bu fonksiyon server başlangıcında bir kez çağrılmalıdır.
 *       Thread-safe değildir, tek thread'den çağrılmalıdır.
 * 
 * @see log_thread_stats()
 * @see thread_monitor()
 */
// Thread monitoring sistemini başlat
void init_thread_monitoring(void) {
    server_start_time = time(NULL);
    memset(active_threads, 0, sizeof(active_threads));
    thread_count = 0;
    PRINTF_LOG("Thread monitoring sistemi aktif\n");
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

/**
 * @brief Client bağlantısını bekleme kuyruğuna ekler
 * @ingroup thread_management
 * 
 * Thread pool dolduğunda gelen client bağlantılarını bekleme kuyruğuna
 * alır. Queue-based connection management sistemi sağlar.
 * 
 * İşlem adımları:
 * 1. Queue boyutu kontrolü yapar (CONFIG_MAX_QUEUE_SIZE)
 * 2. Queue full ise client'ı reject mesajı ile reddeder
 * 3. Yeni queue node oluşturur ve client bilgilerini kaydeder
 * 4. Linked list yapısında queue'ya ekler
 * 5. Queue istatistiklerini günceller
 * 6. Queue processor thread'ine signal gönderir
 * 
 * Queue node bilgileri:
 * - Client socket file descriptor
 * - Client socket address (IP, port)
 * - Queue'ya eklenme zamanı
 * - Next pointer (linked list)
 * 
 * @param client_socket Client'ın socket file descriptor'ı
 * @param client_addr Client'ın socket address yapısı (IP ve port bilgisi)
 * 
 * @note Fonksiyon thread-safe'dir, queue mutex'i ile korunur.
 *       Queue full durumunda client'a açıklayıcı mesaj gönderir.
 * 
 * @warning Bellek ayırma hatası durumunda client bağlantısı kapatılır.
 *          Queue overflow koruması mevcuttur.
 * 
 * Reject mesajı:
 * "QUEUE_FULL: Server kuyruğu dolu, lütfen daha sonra tekrar deneyin"
 * 
 * @see process_queue()
 * @see get_queue_size()
 * @see log_queue_stats()
 * 
 * Örnek çıktı:
 * @code
 * Client queue'ya eklendi: 192.168.1.100:12345 (Queue boyutu: 3/50)
 * @endcode
 * 
 * Kullanım örneği:
 * @code
 * int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
 * if (get_active_thread_count() >= CONFIG_MAX_CLIENTS) {
 *     add_to_queue(client_sock, client_addr);
 * } else {
 *     // Direkt thread oluştur
 * }
 * @endcode
 */
// Client'ı queue'ya ekle
void add_to_queue(int client_socket, struct sockaddr_in client_addr) {
    pthread_mutex_lock(&queue_mutex);
    
    // Queue full kontrolü
    if (queue_size >= CONFIG_MAX_QUEUE_SIZE) {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        PRINTF_LOG("Queue dolu! Client reddediliyor: %s:%d\n", 
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
        PRINTF_LOG("Queue memory allocation hatası!\n");
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
    PRINTF_LOG("Client queue'ya eklendi: %s:%d (Queue boyutu: %d/%d)\n", 
           client_ip, ntohs(client_addr.sin_port), queue_size, CONFIG_MAX_QUEUE_SIZE);
    
    // Queue işleyicisine signal gönder
    pthread_cond_signal(&queue_condition);
    
    pthread_mutex_unlock(&queue_mutex);
}

/**
 * @brief Queue'dan bir client'ı alır ve işleme için thread oluşturur
 * @ingroup thread_management
 * 
 * Bekleme kuyruğundaki ilk client'ı alır ve ona hizmet vermek için
 * yeni thread oluşturur. FIFO (First In, First Out) sırası ile çalışır.
 * 
 * İşlem adımları:
 * 1. Queue boş kontrolü yapar
 * 2. İlk client node'unu queue'dan çıkarır
 * 3. Linked list pointerlarını günceller
 * 4. Client'ın bekleme süresini hesaplar
 * 5. Yeni pthread oluşturur (handle_client fonksiyonu)
 * 6. Thread bilgilerini tracking sistemine ekler
 * 7. Thread'i detach eder (otomatik cleanup)
 * 8. Kullanılan belleği temizler
 * 
 * @return 1 başarılı işlem (client işleme alındı)
 * @return 0 queue boş veya hata durumu
 * 
 * @note Fonksiyon thread-safe'dir, queue mutex'i ile korunur.
 *       Pthread oluşturma hataları handle edilir.
 * 
 * @warning handle_client fonksiyonu external tanımlı olmalıdır.
 *          Thread oluşturma hatası durumunda client socket kapatılır.
 * 
 * @see add_to_queue()
 * @see add_thread_info()
 * @see handle_client()
 * 
 * Örnek çıktı:
 * @code
 * Queue'dan client işleniyor: 192.168.1.100:12345 (Bekleme süresi: 5 saniye)
 * Queue'dan thread oluşturuldu (Thread ID: 140234567890)
 * @endcode
 * 
 * Tipik kullanım (queue processor thread'inde):
 * @code
 * while (get_queue_size() > 0 && get_active_thread_count() < CONFIG_MAX_CLIENTS) {
 *     if (process_queue() == 0) break; // Queue boş
 * }
 * @endcode
 */
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
    
    PRINTF_LOG("Queue'dan client işleniyor: %s:%d (Bekleme süresi: %ld saniye)\n", 
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
        PRINTF_LOG("Queue'dan thread oluşturma hatası!\n");
        free(client_socket_ptr);
        close(client_socket);
        return 0;
    }
    
    // Thread bilgilerini kaydet
    add_thread_info(thread_id, client_socket, client_ip, ntohs(client_addr.sin_port));
    pthread_detach(thread_id);
    
    PRINTF_LOG("Queue'dan thread oluşturuldu (Thread ID: %lu)\n", thread_id);
    
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
    
    PRINTF_LOG("=== QUEUE ISTATISTIKLERI ===\n");
    PRINTF_LOG("Mevcut queue boyutu: %d/%d\n", queue_size, CONFIG_MAX_QUEUE_SIZE);
    PRINTF_LOG("Toplam kuyruklanmış: %d\n", total_queued);
    PRINTF_LOG("Toplam işlenmiş: %d\n", queue_processed);
    
    if (queue_size > 0) {
        PRINTF_LOG("Bekleyen client'ler:\n");
        queue_client_t* current = queue_head;
        int index = 1;
        time_t current_time = time(NULL);
        
        while (current != NULL) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &current->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            time_t wait_time = current_time - current->queue_time;
            
            PRINTF_LOG("  %d. %s:%d (Bekleme: %ld saniye)\n", 
                   index++, client_ip, ntohs(current->client_addr.sin_port), wait_time);
            
            current = current->next;
        }
    }
    
    PRINTF_LOG("===========================\n");
    
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
        PRINTF_LOG("Queue temizleme: %s:%d bağlantısı kapatılıyor\n", 
               client_ip, ntohs(current->client_addr.sin_port));
        
        close(current->client_socket);
        free(current);
        current = next;
    }
    
    queue_head = queue_tail = NULL;
    queue_size = 0;
    
    pthread_mutex_unlock(&queue_mutex);
}

/**
 * @brief Tüm aktif TCP client thread'lerini zorla sonlandırır
 * @ingroup thread_management
 * 
 * Server kapatılması veya acil durum durumunda tüm aktif TCP client
 * bağlantılarını ve thread'lerini temiz bir şekilde sonlandırır.
 * 
 * Sonlandırma adımları:
 * 1. Tüm aktif thread'leri iterate eder
 * 2. Her client socket'ını kapatır (shutdown + close)
 * 3. Thread'leri pthread_cancel ile sonlandırır
 * 4. Thread bilgilerini tracking sisteminden temizler
 * 5. Thread sayacını sıfırlar
 * 6. Konsola sonlandırma raporları yazdırır
 * 
 * Socket kapatma sırası:
 * 1. shutdown(socket, SHUT_RDWR) - Okuma/yazma kanallarını kapat
 * 2. close(socket) - Socket'ı tamamen kapat
 * 3. Socket descriptor'ını -1 ile işaretle
 * 
 * @note Fonksiyon thread-safe'dir, thread mutex'i ile korunur.
 *       Graceful shutdown sağlar, data loss'u minimize eder.
 * 
 * @warning Bu fonksiyon tüm client bağlantılarını ZORLA sonlandırır.
 *          Sadece server shutdown durumunda kullanılmalıdır.
 *          Client'lara bildirim gönderilmez.
 * 
 * @see add_thread_info()
 * @see remove_thread_info()
 * @see clear_queue()
 * 
 * Örnek çıktı:
 * @code
 * Tüm TCP client bağlantıları sonlandırılıyor...
 * TCP client sonlandırılıyor: client_192.168.1.100_12345 (Socket: 8)
 * TCP client sonlandırılıyor: client_192.168.1.101_23456 (Socket: 9)
 * ✓ Tüm TCP client bağlantıları sonlandırıldı
 * @endcode
 * 
 * Kullanım senaryosu:
 * @code
 * void server_shutdown_handler(int sig) {
 *     terminate_all_tcp_clients();
 *     clear_queue();
 *     exit(0);
 * }
 * @endcode
 */
// Tüm TCP client thread'lerini sonlandır
void terminate_all_tcp_clients(void) {
    pthread_mutex_lock(&thread_mutex);
    
    PRINTF_LOG("Tüm TCP client bağlantıları sonlandırılıyor...\n");
    
    for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {
        if (active_threads[i].is_active) {
            PRINTF_LOG("TCP client sonlandırılıyor: %s (Socket: %d)\n", 
                   active_threads[i].thread_name, active_threads[i].client_socket);
            
            // Client socket'ını kapat
            if (active_threads[i].client_socket >= 0) {
                shutdown(active_threads[i].client_socket, SHUT_RDWR);
                close(active_threads[i].client_socket);
                active_threads[i].client_socket = -1;
            }
            
            // Thread'i cancel et
            pthread_cancel(active_threads[i].thread_id);
            
            // Thread bilgilerini temizle
            memset(&active_threads[i], 0, sizeof(thread_info_t));
            thread_count--;
        }
    }
    
    PRINTF_LOG("✓ Tüm TCP client bağlantıları sonlandırıldı\n");
    
    pthread_mutex_unlock(&thread_mutex);
}