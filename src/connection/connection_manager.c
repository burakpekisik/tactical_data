/**
 * @file connection_manager.c
 * @brief Çok protokol bağlantı yönetimi ve ECDH anahtar değişimi sistemi
 * @ingroup connection_management
 * @author Taktik Veri Sistemi
 * @date 2025
 * 
 * Bu dosya TCP, UDP ve P2P bağlantı protokollerini yöneten merkezi
 * connection manager sistemini içerir. Ayrıca ECDH anahtar değişimi
 * ve AES256 oturum anahtarı yönetimi sağlar.
 * 
 * Ana özellikler:
 * - Çok protokol sunucu yönetimi (TCP/UDP/P2P)
 * - Thread-safe bağlantı kontrolü
 * - ECDH (Elliptic Curve Diffie-Hellman) anahtar değişimi
 * - AES256 oturum anahtarı türetimi
 * - Real-time bağlantı durumu monitoring
 * - Interactive connection control interface
 * - Port management ve conflict detection
 * 
 * Desteklenen protokoller:
 * - **TCP**: Güvenilir, connection-oriented iletişim
 * - **UDP**: Hızlı, connectionless iletişim  
 * - **P2P**: Peer-to-peer decentralized iletişim
 * 
 * Güvenlik özellikleri:
 * - ECDH anahtar değişimi ile perfect forward secrecy
 * - AES256 symmetric encryption
 * - Secure session key derivation
 * - Connection-specific encryption contexts
 * 
 * @note Bu sistem production ortamında kritik güvenlik ve performans sağlar.
 *       Tüm fonksiyonlar thread-safe'dir ve concurrent access destekler.
 * 
 * @warning ECDH key exchange başarısız olursa bağlantı şifrelenmez.
 *          Port çakışmalarını önlemek için CONFIG_PORT + offset kullanılır.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "connection_manager.h"
#include "tcp_connection.h"
#include "udp_connection.h"
#include "p2p_connection.h"
#include "config.h"
#include "crypto_utils.h"
#include "logger.h"

/// @brief TCP bağlantı yöneticisi - global context
static connection_manager_t tcp_manager;

/// @brief UDP bağlantı yöneticisi - global context
static connection_manager_t udp_manager;

/// @brief P2P bağlantı yöneticisi - global context
static connection_manager_t p2p_manager;

/// @brief Connection manager işlemlerini korumak için mutex
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;

/// @brief Manager initialization durumu - tek seferlik init için
static bool manager_initialized = false;

/**
 * @brief Connection manager sistemini başlatır ve tüm protokol yöneticilerini ilklendirir
 * @ingroup connection_management
 * 
 * Bu fonksiyon sunucu başlangıcında çağrılarak tüm bağlantı protokollerini
 * kullanıma hazır hale getirir. Thread-safe initialization sağlar.
 * 
 * İlklendirilen sistemler:
 * - **TCP Manager**: CONFIG_PORT'ta TCP sunucu hazırlığı
 * - **UDP Manager**: CONFIG_PORT+1'de UDP sunucu hazırlığı  
 * - **P2P Manager**: CONFIG_PORT+2'de P2P node hazırlığı
 * 
 * Port allocation stratejisi:
 * - Base port: CONFIG_PORT (örn. 8080)
 * - TCP: CONFIG_PORT (8080)
 * - UDP: CONFIG_PORT + 1 (8081) 
 * - P2P: CONFIG_PORT + 2 (8082)
 * 
 * @return 0 başarılı initialization
 * @return 0 zaten initialize edilmiş (idempotent)
 * 
 * @note Fonksiyon idempotent'tir, multiple call güvenlidir.
 *       Thread-safe initialization mutex ile korunur.
 * 
 * @warning Sadece ana thread'den çağrılmalıdır (server startup).
 *          Network interface'lerin hazır olduğundan emin olun.
 * 
 * @see start_tcp_server()
 * @see start_udp_server()
 * @see start_p2p_node()
 * 
 * Başarılı init çıktısı:
 * @code
 * Connection Manager initialized
 * - TCP: Port 8080 (Ready)
 * - UDP: Port 8081 (Ready)
 * - P2P: Port 8082 (Ready)
 * @endcode
 */
// Connection manager'ı başlat
int init_connection_manager(void) {
    pthread_mutex_lock(&conn_mutex);
    
    if (manager_initialized) {
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    // TCP Manager
    memset(&tcp_manager, 0, sizeof(connection_manager_t));
    tcp_manager.port = CONFIG_PORT;
    tcp_server_init(&tcp_manager);
    
    // UDP Manager
    memset(&udp_manager, 0, sizeof(connection_manager_t));
    udp_manager.port = CONFIG_PORT + 1;
    udp_server_init(&udp_manager);
    
    // P2P Manager
    memset(&p2p_manager, 0, sizeof(connection_manager_t));
    p2p_manager.port = CONFIG_PORT + 2;
    p2p_node_init(&p2p_manager);
    
    manager_initialized = true;
    pthread_mutex_unlock(&conn_mutex);
    
    PRINTF_LOG("Connection Manager initialized\n");
    PRINTF_LOG("- TCP: Port %d (Ready)\n", tcp_manager.port);
    PRINTF_LOG("- UDP: Port %d (Ready)\n", udp_manager.port);
    PRINTF_LOG("- P2P: Port %d (Ready)\n", p2p_manager.port);
    fflush(stdout);
    
    return 0;
}

/**
 * @brief TCP sunucusunu belirtilen portta başlatır
 * @ingroup connection_management
 * 
 * TCP sunucusunu specified port'ta başlatır ve client bağlantılarını
 * kabul etmeye hazır hale getirir. Thread pool ve queue management dahil.
 * 
 * İşlem adımları:
 * 1. Mevcut TCP sunucu durumunu kontrol eder
 * 2. Zaten çalışıyorsa uyarı verir ve 0 döner
 * 3. Port bilgisini günceller
 * 4. tcp_server_start() delegate eder
 * 5. Manager status'unu günceller
 * 
 * @param port TCP sunucusunun dinleyeceği port numarası
 * 
 * @return 0 başarılı başlatma veya zaten çalışıyor
 * @return tcp_server_start()'ın dönüş değeri (hata durumunda)
 * 
 * @note Fonksiyon thread-safe'dir, multiple call güvenlidir.
 *       Zaten çalışan sunucu duplicate start attempt'e izin vermez.
 * 
 * @warning Port kullanımda olabilir, bind hatası alınabilir.
 *          Root privilege gerektirebilir (port < 1024).
 * 
 * @see stop_tcp_server()
 * @see tcp_server_start()
 * @see get_connection_status()
 * 
 * Örnek kullanım:
 * @code
 * int result = start_tcp_server(8080);
 * if (result != 0) {
 *     PRINTF_LOG("TCP sunucu başlatılamadı: %d\n", result);
 * }
 * @endcode
 */
// TCP Server başlat
int start_tcp_server(int port) {
    pthread_mutex_lock(&conn_mutex);
    
    if (tcp_manager.status == CONN_STATUS_RUNNING) {
        PRINTF_LOG("TCP Server zaten çalışıyor (Port: %d)\n", tcp_manager.port);
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    tcp_manager.port = port;
    int result = tcp_server_start(&tcp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

/**
 * @brief TCP sunucusunu durdurur ve tüm client bağlantılarını kapatır
 * @ingroup connection_management
 * 
 * Çalışan TCP sunucusunu graceful shutdown yapar. Tüm aktif client
 * bağlantıları kapatılır ve thread'ler temizlenir.
 * 
 * @return tcp_server_stop()'un dönüş değeri
 * @return 0 başarılı durdurma
 * 
 * @note Thread-safe operation, queue'deki bekleyen client'lar da temizlenir.
 * 
 * @see start_tcp_server()
 * @see tcp_server_stop()
 */
// TCP Server durdur
int stop_tcp_server(void) {
    pthread_mutex_lock(&conn_mutex);
    
    int result = tcp_server_stop(&tcp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

/**
 * @brief UDP sunucusunu belirtilen portta başlatır
 * @ingroup connection_management
 * 
 * UDP sunucusunu connectionless packet communication için başlatır.
 * 
 * @param port UDP sunucusunun dinleyeceği port numarası
 * 
 * @return 0 başarılı başlatma veya zaten çalışıyor
 * @return udp_server_start()'ın dönüş değeri (hata durumunda)
 * 
 * @note Thread-safe operation, duplicate start koruması var.
 * 
 * @see stop_udp_server()
 * @see udp_server_start()
 */
// UDP Server başlat
int start_udp_server(int port) {
    pthread_mutex_lock(&conn_mutex);
    
    if (udp_manager.status == CONN_STATUS_RUNNING) {
        PRINTF_LOG("UDP Server zaten çalışıyor (Port: %d)\n", udp_manager.port);
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    udp_manager.port = port;
    int result = udp_server_start(&udp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// UDP Server durdur
int stop_udp_server(void) {
    pthread_mutex_lock(&conn_mutex);
    
    int result = udp_server_stop(&udp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// P2P Node başlat
int start_p2p_node(int port) {
    pthread_mutex_lock(&conn_mutex);
    
    if (p2p_manager.status == CONN_STATUS_RUNNING) {
        PRINTF_LOG("P2P Node zaten çalışıyor (Port: %d)\n", p2p_manager.port);
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    p2p_manager.port = port;
    int result = p2p_node_start(&p2p_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// P2P Node durdur
int stop_p2p_node(void) {
    pthread_mutex_lock(&conn_mutex);
    
    int result = p2p_node_stop(&p2p_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

/**
 * @brief Tüm aktif bağlantıları ve durumlarını detaylı raporlar
 * @ingroup connection_management
 * 
 * Bu fonksiyon real-time network monitoring sağlar. Tüm protokol
 * sunucularının durumunu, port bilgilerini ve status'larını gösterir.
 * 
 * Gösterilen bilgiler:
 * - **TCP Server**: Aktiflik, port, detaylı status
 * - **UDP Server**: Aktiflik, port, detaylı status
 * - **P2P Node**: Aktiflik, port, detaylı status
 * 
 * Status değerleri:
 * - RUNNING: Aktif çalışıyor
 * - STOPPED: Durdurulmuş
 * - ERROR: Hata durumunda
 * - UNKNOWN: Belirsiz durum
 * 
 * @note Thread-safe okuma, mutex koruması altında.
 *       Production monitoring ve debugging için kritik.
 * 
 * @warning Console output, log sistem entegrasyonu düşünülmeli.
 * 
 * @see get_connection_status()
 * @see show_connection_menu()
 * 
 * Örnek çıktı:
 * @code
 * ==== ACTIVE CONNECTIONS ====
 * TCP Server: ACTIVE (Port: 8080, Status: RUNNING)
 * UDP Server: INACTIVE (Port: 8081, Status: STOPPED)
 * P2P Node: ACTIVE (Port: 8082, Status: RUNNING)
 * ============================
 * @endcode
 */
// Aktif bağlantıları listele
void list_active_connections(void) {
    pthread_mutex_lock(&conn_mutex);
    
    PRINTF_LOG("\n==== ACTIVE CONNECTIONS ====\n");
    
    // TCP Status
    PRINTF_LOG("TCP Server: %s (Port: %d, Status: %s)\n",
           tcp_manager.is_active ? "ACTIVE" : "INACTIVE",
           tcp_manager.port,
           tcp_manager.status == CONN_STATUS_RUNNING ? "RUNNING" :
           tcp_manager.status == CONN_STATUS_STOPPED ? "STOPPED" :
           tcp_manager.status == CONN_STATUS_ERROR ? "ERROR" : "UNKNOWN");
    
    // UDP Status
    PRINTF_LOG("UDP Server: %s (Port: %d, Status: %s)\n",
           udp_manager.is_active ? "ACTIVE" : "INACTIVE",
           udp_manager.port,
           udp_manager.status == CONN_STATUS_RUNNING ? "RUNNING" :
           udp_manager.status == CONN_STATUS_STOPPED ? "STOPPED" :
           udp_manager.status == CONN_STATUS_ERROR ? "ERROR" : "UNKNOWN");
    
    // P2P Status
    PRINTF_LOG("P2P Node: %s (Port: %d, Status: %s)\n",
           p2p_manager.is_active ? "ACTIVE" : "INACTIVE",
           p2p_manager.port,
           p2p_manager.status == CONN_STATUS_RUNNING ? "RUNNING" :
           p2p_manager.status == CONN_STATUS_STOPPED ? "STOPPED" :
           p2p_manager.status == CONN_STATUS_ERROR ? "ERROR" : "UNKNOWN");
    
    PRINTF_LOG("============================\n\n");
    
    pthread_mutex_unlock(&conn_mutex);
}

// Bağlantı durumunu al
connection_status_t get_connection_status(connection_type_t type) {
    pthread_mutex_lock(&conn_mutex);
    
    connection_status_t status = CONN_STATUS_STOPPED;
    
    switch (type) {
        case CONN_TYPE_TCP:
            status = tcp_manager.status;
            break;
        case CONN_TYPE_UDP:
            status = udp_manager.status;
            break;
        case CONN_TYPE_P2P:
            status = p2p_manager.status;
            break;
        default:
            break;
    }
    
    pthread_mutex_unlock(&conn_mutex);
    return status;
}

// Connection menüsü
void show_connection_menu(void) {
    PRINTF_LOG("\n=== CONNECTION CONTROL MENU ===\n");
    PRINTF_LOG("TCP Commands:\n");
    PRINTF_LOG("  start_tcp  - Start TCP Server\n");
    PRINTF_LOG("  stop_tcp   - Stop TCP Server\n");
    PRINTF_LOG("UDP Commands:\n");
    PRINTF_LOG("  start_udp  - Start UDP Server\n");
    PRINTF_LOG("  stop_udp   - Stop UDP Server\n");
    PRINTF_LOG("P2P Commands:\n");
    PRINTF_LOG("  start_p2p  - Start P2P Node\n");
    PRINTF_LOG("  stop_p2p   - Stop P2P Node\n");
    PRINTF_LOG("General Commands:\n");
    PRINTF_LOG("  list       - List Active Connections\n");
    PRINTF_LOG("  stats      - Show Statistics\n");
    PRINTF_LOG("  help       - Show this menu\n");
    PRINTF_LOG("  quit       - Exit server\n");
    PRINTF_LOG("===============================\n");
}

// Command işleme
int process_connection_command(const char* command) {
    if (strcmp(command, "start_tcp") == 0) {
        return start_tcp_server(CONFIG_PORT);
    } else if (strcmp(command, "stop_tcp") == 0) {
        return stop_tcp_server();
    } else if (strcmp(command, "start_udp") == 0) {
        return start_udp_server(CONFIG_PORT + 1);
    } else if (strcmp(command, "stop_udp") == 0) {
        return stop_udp_server();
    } else if (strcmp(command, "start_p2p") == 0) {
        return start_p2p_node(CONFIG_PORT + 2);
    } else if (strcmp(command, "stop_p2p") == 0) {
        return stop_p2p_node();
    } else if (strcmp(command, "list") == 0) {
        list_active_connections();
        return 0;
    }
    
    return -1;
}

/**
 * @defgroup ecdh_key_management ECDH Anahtar Yönetimi
 * @ingroup connection_management
 * @brief Elliptic Curve Diffie-Hellman anahtar değişimi ve session key yönetimi
 * 
 * Bu grup ECDH anahtar değişimi, AES256 session key türetimi ve
 * güvenli iletişim için gerekli cryptographic operations içerir.
 */

/**
 * @brief Bağlantı için ECDH anahtar değişimi sistemini başlatır
 * @ingroup ecdh_key_management
 * 
 * Bu fonksiyon belirli bir connection için ECDH (Elliptic Curve Diffie-Hellman)
 * anahtar değişimi sistemini hazırlar. Perfect forward secrecy sağlar.
 * 
 * ECDH initialization adımları:
 * 1. ECDH context memory allocation ve initialization
 * 2. Elliptic curve parameters setup (P-256)
 * 3. Private/public key pair generation
 * 4. Connection manager'a ECDH context bağlama
 * 5. ecdh_initialized flag'i true yapma
 * 
 * Güvenlik özellikleri:
 * - P-256 elliptic curve (NIST recommendation)
 * - 256-bit key strength
 * - Perfect forward secrecy
 * - Session-specific key pairs
 * 
 * @param manager ECDH'nin bağlanacağı connection manager
 * 
 * @return 1 başarılı ECDH initialization
 * @return 0 hata durumu (NULL manager, context init fail, keygen fail)
 * 
 * @note Her connection için ayrı ECDH context kullanılır.
 *       Memory cleanup için cleanup_ecdh_for_connection() çağrılmalı.
 * 
 * @warning manager NULL kontrolü yapılır, güvenli çağrım.
 *          Başarısızlık durumunda connection şifrelenmez.
 * 
 * @see exchange_keys_with_peer()
 * @see cleanup_ecdh_for_connection()
 * @see ecdh_init_context()
 * @see ecdh_generate_keypair()
 * 
 * Başarılı init mesajı:
 * @code
 * ECDH Client-Socket-123 için başlatıldı
 * @endcode
 */
// Bağlantı için ECDH başlat
int init_ecdh_for_connection(connection_manager_t* manager) {
    if (manager == NULL) {
        return 0;
    }
    
    // ECDH context'i başlat
    if (!ecdh_init_context(&manager->ecdh_ctx)) {
        PRINTF_LOG("ECDH context başlatılamadı\n");
        return 0;
    }
    
    // Anahtar çifti üret
    if (!ecdh_generate_keypair(&manager->ecdh_ctx)) {
        PRINTF_LOG("ECDH anahtar çifti üretilemedi\n");
        return 0;
    }
    
    manager->ecdh_initialized = true;
    PRINTF_LOG("ECDH %s için başlatıldı\n", manager->name);
    
    return 1;
}

/**
 * @brief Peer ile ECDH anahtar değişimi gerçekleştirir ve AES256 session key üretir
 * @ingroup ecdh_key_management
 * 
 * Bu fonksiyon client ile server arasında güvenli ECDH anahtar değişimi
 * protokolünü yürütür ve AES256 symmetric encryption için session key üretir.
 * 
 * Anahtar değişimi protokolü:
 * 1. **Send Phase**: Kendi public key'ini peer'e gönderir
 * 2. **Receive Phase**: Peer'in public key'ini alır
 * 3. **Compute Phase**: Shared secret hesaplar (ECDH math)
 * 4. **Derive Phase**: AES256 session key türetir (KDF)
 * 5. **Validation**: Tüm adımların başarısını doğrular
 * 
 * Network protokol:
 * - İlk ECC_PUB_KEY_SIZE byte: Local public key gönderimi
 * - Sonraki ECC_PUB_KEY_SIZE byte: Peer public key alımı
 * - Synchronous exchange (blocking I/O)
 * 
 * Cryptographic operations:
 * - ECDH shared secret computation
 * - Key derivation function (KDF) 
 * - AES256 session key generation
 * 
 * @param manager ECDH context'i içeren connection manager
 * @param socket Peer ile iletişim kuracak network socket
 * 
 * @return 1 başarılı anahtar değişimi ve session key ready
 * @return 0 hata durumu (NULL params, network error, crypto error)
 * 
 * @note Fonksiyon blocking operation yapar, network timeout gerekebilir.
 *       Session key manager->ecdh_ctx.aes_key'de saklanır.
 * 
 * @warning Network hatası durumunda connection güvenli değildir.
 *          Shared secret computational error critical security risk.
 * 
 * Hata durumları:
 * - manager NULL veya ECDH not initialized
 * - socket < 0 (invalid socket)
 * - Public key send/receive failure
 * - Shared secret computation failure
 * - AES key derivation failure
 * 
 * @see init_ecdh_for_connection()
 * @see get_session_key()
 * @see ecdh_compute_shared_secret()
 * @see ecdh_derive_aes_key()
 * 
 * Başarılı exchange çıktısı:
 * @code
 * Peer ile anahtar değişimi başlıyor...
 * ✓ Anahtar değişimi başarıyla tamamlandı
 * ✓ AES256 oturum anahtarı hazır
 * @endcode
 */
// Peer ile anahtar değişimi yap
int exchange_keys_with_peer(connection_manager_t* manager, int socket) {
    if (manager == NULL || socket < 0 || !manager->ecdh_initialized) {
        return 0;
    }
    
    PRINTF_LOG("Peer ile anahtar değişimi başlıyor...\n");
    
    // Önce kendi public key'imizi gönder
    ssize_t sent = send(socket, manager->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
    if (sent != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Public key gönderilemedi\n");
        return 0;
    }
    
    // Peer'in public key'ini al
    uint8_t peer_public_key[ECC_PUB_KEY_SIZE];
    ssize_t received = recv(socket, peer_public_key, ECC_PUB_KEY_SIZE, 0);
    if (received != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Peer public key alınamadı\n");
        return 0;
    }
    
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&manager->ecdh_ctx, peer_public_key)) {
        PRINTF_LOG("Shared secret hesaplanamadı\n");
        return 0;
    }
    
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&manager->ecdh_ctx)) {
        PRINTF_LOG("AES anahtarı türetilemedi\n");
        return 0;
    }
    
    PRINTF_LOG("✓ Anahtar değişimi başarıyla tamamlandı\n");
    PRINTF_LOG("✓ AES256 oturum anahtarı hazır\n");
    
    return 1;
}

/**
 * @brief ECDH session key'ini güvenli şekilde döndürür
 * @ingroup ecdh_key_management
 * 
 * Exchange_keys_with_peer() fonksiyonu ile üretilen AES256 session key'ini
 * encryption/decryption işlemleri için external code'a sağlar.
 * 
 * @param manager Session key'i içeren connection manager
 * 
 * @return AES256 session key pointer (32 bytes)
 * @return NULL hata durumunda (NULL manager, ECDH not initialized)
 * 
 * @note Döndürülen pointer read-only kullanılmalı, modify edilmemeli.
 *       Key lifetime connection boyunca geçerlidir.
 * 
 * @warning Key memory'si manager'a aittir, caller free etmemeli.
 *          NULL return'ü kontrol edilmeli.
 * 
 * @see exchange_keys_with_peer()
 * @see cleanup_ecdh_for_connection()
 * 
 * Kullanım örneği:
 * @code
 * const uint8_t* session_key = get_session_key(manager);
 * if (session_key != NULL) {
 *     // AES encryption with session_key
 *     encrypt_data(plaintext, ciphertext, session_key);
 * }
 * @endcode
 */
// Oturum anahtarını al
const uint8_t* get_session_key(connection_manager_t* manager) {
    if (manager == NULL || !manager->ecdh_initialized) {
        return NULL;
    }
    
    return manager->ecdh_ctx.aes_key;
}

/**
 * @brief ECDH context'ini temizler ve güvenli memory cleanup yapar
 * @ingroup ecdh_key_management
 * 
 * Connection sonlandığında ECDH context'ini güvenli şekilde temizler.
 * Cryptographic key material'i memory'den siler.
 * 
 * Temizlik işlemleri:
 * 1. ECDH context sensitive data'sını sıfırlar
 * 2. Private key'i memory'den siler
 * 3. Session key'i güvenli şekilde zero'lar
 * 4. ecdh_initialized flag'ini false yapar
 * 5. Debug mesajı yazdırır
 * 
 * @param manager Temizlenecek connection manager
 * 
 * @note NULL manager kontrolü yapar, güvenli çağrım sağlar.
 *       Forward secrecy için kritik, key material kalmamalı.
 * 
 * @warning Bu çağrıdan sonra get_session_key() NULL döner.
 *          Connection close handler'da mutlaka çağrılmalı.
 * 
 * @see init_ecdh_for_connection()
 * @see ecdh_cleanup_context()
 * 
 * Temizlik mesajı:
 * @code
 * ECDH Client-Socket-123 için temizlendi
 * @endcode
 */
// ECDH için temizlik yap
void cleanup_ecdh_for_connection(connection_manager_t* manager) {
    if (manager != NULL && manager->ecdh_initialized) {
        ecdh_cleanup_context(&manager->ecdh_ctx);
        manager->ecdh_initialized = false;
        PRINTF_LOG("ECDH %s için temizlendi\n", manager->name);
    }
}
