#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/wait.h>
#include "logger.h"
#include "queue_manager.h"
#include "config.h"
#include "thread_monitor.h"
#include <unistd.h>

/**
 * @brief Connection queue'yu işleyen background thread fonksiyonu
 * @ingroup server
 * 
 * Bu thread sürekli çalışarak bekleyen client bağlantılarını kontrol eder.
 * Thread pool dolduğunda queue'da bekleyen client'ları işleme alır.
 * 
 * İşlem döngüsü:
 * 1. Queue'da bekleyen client olup olmadığını kontrol eder
 * 2. Aktif thread sayısının limiti aşıp aşmadığını kontrol eder
 * 3. Her iki koşul sağlanırsa queue'dan client alır
 * 4. Yeni thread oluşturur ve client'ı işleme başlatır
 * 5. Konfigüre edilmiş aralıklarla döngüyü tekrarlar
 * 
 * Kontrol parametreleri:
 * - Queue boyutu: get_queue_size()
 * - Aktif thread sayısı: get_active_thread_count()
 * - Maksimum thread limiti: CONFIG_MAX_CLIENTS
 * - Kontrol aralığı: CONFIG_QUEUE_CHECK_INTERVAL
 * 
 * @param arg Kullanılmıyor.
 * 
 * @return NULL (pthread için void* dönüş)
 * 
 * @note Bu thread sunucu yaşam döngüsü boyunca sürekli çalışır.
 *       Thread oluşturma sonrası kısa bekleme yaparak performansı optimize eder.
 * 
 * @warning Thread infinite loop içinde çalışır, normal şartlarda sonlanmaz.
 *          Sunucu kapatılana kadar aktif kalır.
 * 
 * İstatistik çıktısı:
 * @code
 * 🔄 Queue işleniyor... (Queue: 3, Aktif: 8/10)
 * @endcode
 * 
 * @see get_queue_size()
 * @see get_active_thread_count()
 * @see process_queue()
 */
// Queue processor thread - boş slot olduğunda queue'yu işler
void* queue_processor(void* arg) {
    (void)arg; // unused parameter warning'ini bastır
    
    PRINTF_LOG("Queue processor thread başlatıldı\n");
    fflush(stdout);
    
    while (1) {
        // Queue'da client var mı ve boş thread slot'u var mı kontrol et
        while (get_queue_size() > 0 && get_active_thread_count() < CONFIG_MAX_CLIENTS) {
            PRINTF_LOG("🔄 Queue işleniyor... (Queue: %d, Aktif: %d/%d)\n", 
                   get_queue_size(), get_active_thread_count(), CONFIG_MAX_CLIENTS);
            
            if (process_queue() == 0) {
                break; // Queue boş
            }
            
            // Thread oluşturma sonrası kısa bekleme
            sleep(100000); // 100ms
        }
        
        // Queue kontrol aralığı
        sleep(CONFIG_QUEUE_CHECK_INTERVAL);
    }
    
    return NULL;
}

// Queue fonksiyonları
void task_queue_init(task_queue_t* q, int max_size) {
    q->head = q->tail = NULL;
    q->size = 0;
    q->max_size = max_size;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

void task_queue_destroy(task_queue_t* q) {
    pthread_mutex_lock(&q->mutex);
    task_node_t* cur = q->head;
    while (cur) {
        task_node_t* next = cur->next;
        free(cur);
        cur = next;
    }
    q->head = q->tail = NULL;
    q->size = 0;
    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

int task_queue_push(task_queue_t* q, void (*func)(void*), void* arg) {
    PRINTF_LOG("[DEBUG][task_queue_push] q=%p, func=%p, arg=%p\n", (void*)q, (void*)func, arg);
    if (!q) {
        PRINTF_LOG("[ERROR][task_queue_push] q is NULL!\n");
        return -1;
    }
    if (!func) {
        PRINTF_LOG("[ERROR][task_queue_push] func is NULL!\n");
        return -1;
    }
    if (!arg) {
        PRINTF_LOG("[ERROR][task_queue_push] arg is NULL!\n");
        return -1;
    }
    pthread_mutex_lock(&q->mutex);
    if (q->size >= q->max_size) {
        pthread_mutex_unlock(&q->mutex);
        return -1; // Queue full
    }
    task_node_t* node = malloc(sizeof(task_node_t));
    node->func = func;
    node->arg = arg;
    node->next = NULL;
    if (q->tail) q->tail->next = node;
    else q->head = node;
    q->tail = node;
    q->size++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

task_node_t* task_queue_pop(task_queue_t* q) {
    pthread_mutex_lock(&q->mutex);
    while (q->size == 0) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }
    task_node_t* node = q->head;
    if (node) {
        q->head = node->next;
        if (!q->head) q->tail = NULL;
        q->size--;
    }
    pthread_mutex_unlock(&q->mutex);
    return node;
}

// Thread pool worker
void* thread_pool_worker(void* arg) {
    thread_pool_t* pool = (thread_pool_t*)arg;
    PRINTF_LOG("[DEBUG][thread_pool_worker] started, pool=%p, running=%d\n", pool, pool ? pool->running : -1);
    while (pool->running) {
        task_node_t* task = task_queue_pop(pool->queue);
        PRINTF_LOG("[DEBUG][thread_pool_worker] got task node=%p\n", task);
        if (task) {
            PRINTF_LOG("[DEBUG][thread_pool_worker] task->func=%p, task->arg=%p\n", (void*)task->func, task->arg);
            if (!task->func) {
                PRINTF_LOG("[ERROR][thread_pool_worker] task->func is NULL!\n");
                free(task);
                continue;
            }
            if (!task->arg) {
                PRINTF_LOG("[ERROR][thread_pool_worker] task->arg is NULL!\n");
                free(task);
                continue;
            }
            // Defensive: try to print first 16 bytes of arg as hex
            unsigned char* arg_bytes = (unsigned char*)task->arg;
            PRINTF_LOG("[DEBUG][thread_pool_worker] arg first bytes: ");
            for (int i = 0; i < 16; i++) PRINTF_LOG("%02X ", arg_bytes[i]);
            PRINTF_LOG("\n");
            PRINTF_LOG("[DEBUG][thread_pool_worker] Calling task function...\n");
            task->func(task->arg);
            PRINTF_LOG("[DEBUG][thread_pool_worker] Task function returned.\n");
            free(task);
        }
    }
    PRINTF_LOG("[DEBUG][thread_pool_worker] exiting, pool=%p\n", pool);
    return NULL;
}

// Thread pool başlat
void thread_pool_init(thread_pool_t* pool, int thread_count, int queue_max_size) {
    pool->thread_count = thread_count;
    pool->threads = malloc(sizeof(pthread_t) * thread_count);
    pool->queue = malloc(sizeof(task_queue_t));
    task_queue_init(pool->queue, queue_max_size);
    pool->running = 1;
    for (int i = 0; i < thread_count; i++) {
        pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool);
    }
}

// Thread pool'a task ekle
int thread_pool_submit(thread_pool_t* pool, void (*func)(void*), void* arg) {
    PRINTF_LOG("[DEBUG][thread_pool_submit] pool=%p, pool->queue=%p, func=%p, arg=%p\n", (void*)pool, (void*)(pool ? pool->queue : NULL), (void*)func, arg);
    if (!pool) {
        PRINTF_LOG("[ERROR][thread_pool_submit] pool is NULL!\n");
        return -1;
    }
    if (!pool->queue) {
        PRINTF_LOG("[ERROR][thread_pool_submit] pool->queue is NULL!\n");
        return -1;
    }
    if (!func) {
        PRINTF_LOG("[ERROR][thread_pool_submit] func is NULL!\n");
        return -1;
    }
    if (!arg) {
        PRINTF_LOG("[ERROR][thread_pool_submit] arg is NULL!\n");
        return -1;
    }
    return task_queue_push(pool->queue, func, arg);
}

// Thread pool'u durdur
void thread_pool_destroy(thread_pool_t* pool) {
    pool->running = 0;
    // Worker'ları uyandır
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_cond_broadcast(&pool->queue->cond);
    }
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    task_queue_destroy(pool->queue);
    free(pool->queue);
    free(pool->threads);
}