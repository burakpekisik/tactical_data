#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/wait.h>
#include "logger.h"
#include "queue_manager.h"
#include "config.h"
#include "thread_monitor.h"

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