/**
 * @file client_wrapper.h
 * @brief Qt Client ile C client kodları arasındaki köprü sınıfı
 * @details Bu sınıf Qt tabanlı GUI ile C dilinde yazılmış encrypted client
 *          kodları arasında bağlantı kurar. TCP/UDP bağlantı yönetimi ve
 *          şifreli veri gönderim işlemlerini sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 */

#ifndef CLIENT_WRAPPER_H
#define CLIENT_WRAPPER_H

#include <QObject>
#include <QString>
#include <QThread>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QTimer>
#include <QMutex>

extern "C" {
    #include "encrypted_client.h"
    #include "crypto_utils.h"
    #include "protocol_manager.h"
    #include "config.h"
    #include "logger.h"
    #include "cJSON.h"
}

/**
 * @brief Qt Client wrapper sınıfı
 * @details C client kodları ile Qt GUI arasında köprü görevi görür.
 *          Thread-safe şekilde sunucu bağlantısı kurar ve veri gönderir.
 */
class ClientWrapper : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Bağlantı durumu enum'u
     */
    enum ConnectionStatus {
        Disconnected = 0,
        Connecting = 1,
        Connected = 2,
        Error = 3
    };

    /**
     * @brief Veri gönderim sonucu enum'u
     */
    enum SendResult {
        SendSuccess = 0,
        SendError = 1,
        NotConnected = 2,
        InvalidData = 3
    };

    enum class ConnectionType { TCP, UDP, P2P };

    explicit ClientWrapper(QObject *parent = nullptr);
    ~ClientWrapper();

    // Bağlantı durumu
    ConnectionStatus getConnectionStatus() const;
    bool isConnected() const;

    // JWT token set/get fonksiyonları
    void setJwtToken(const QString& token) { jwtToken = token; }
    QString getJwtToken() const { return jwtToken; }

public slots:
    /**
     * @brief Sunucuya bağlantı kurar
     * @param host Sunucu IP adresi
     * @param port Sunucu port numarası
     */
    void connectToServer(const QString& host, int port);

    /**
     * @brief Sunucu bağlantısını keser
     */
    void disconnectFromServer();

    /**
     * @brief Taktik veri gönderir
     * @param latitude Enlem koordinatı
     * @param longitude Boylam koordinatı
     * @param dataType Veri tipi
     * @param message Kullanıcı mesajı
     * @param encrypted Şifreli gönderim (true/false)
     */
    void sendTacticalData(double latitude, double longitude, 
                         const QString& dataType, const QString& message, 
                         bool encrypted = true);

    /**
     * @brief JSON dosya gönderir
     * @param filePath Dosya yolu
     * @param encrypted Şifreli gönderim (true/false)
     */
    void sendJsonFile(const QString& filePath, bool encrypted = true);

    // Fallback ve alternatif bağlantı fonksiyonları
    bool connectUdp(const QString& host, int port);
    bool connectP2p(const QString& host, int port);
    bool trySendWithFallback(const QString& jsonString, bool encrypted);
    ConnectionType getCurrentConnectionType() const { return currentType; }
    void setCurrentConnectionType(ConnectionType type) { currentType = type; }

    // --- PUBLIC ---
    QString createTacticalDataJson(double latitude, double longitude, 
                                  const QString& dataType, const QString& message);

    // --- Fallback için UDP ECDH handshake fonksiyonu ---
    bool udpEcdhHandshake(QByteArray& outAesKey);

    // --- Fallback için P2P ECDH handshake fonksiyonu ---
    bool p2pEcdhHandshake(QByteArray& outAesKey);

    // --- Pending JSON gönderimlerini yönet ---
    void sendAllPendingJson(bool encrypted);
    bool trySendJsonInternal(const QString& jsonString, bool encrypted);
    void saveJsonToPending(const QString& jsonString);

    // --- Rapor sorgulama ---
    void getReports();

signals:
    /**
     * @brief Bağlantı durumu değiştiğinde emit edilir
     * @param status Yeni bağlantı durumu
     * @param message Durum mesajı
     */
    void connectionStatusChanged(ConnectionStatus status, const QString& message);

    /**
     * @brief Veri gönderim sonucunda emit edilir
     * @param result Gönderim sonucu
     * @param message Sonuç mesajı
     */
    void dataSendResult(SendResult result, const QString& message);

    /**
     * @brief Sunucudan veri alındığında emit edilir
     * @param data Alınan veri
     */
    void dataReceived(const QString& data);

    /**
     * @brief Log mesajı emit edilir
     * @param message Log mesajı
     */
    void logMessage(const QString& message);

    /**
     * @brief Raporlar alındığında emit edilir
     * @param reports Alınan raporlar
     */
    void reportsReceived(const QJsonArray& reports);

    /**
     * @brief ECDH tamamlandığında emit edilir
     */
    void ecdhHandshakeCompleted(); // <-- ECDH tamamlandığında tetiklenecek sinyal

private slots:
    void onSocketConnected();
    void onSocketDisconnected();
    void onSocketError();
    void onDataReceived();
    void onConnectionTimeout();

private:
    // Network bileşenleri
    QTcpSocket *tcpSocket;
    QUdpSocket *udpSocket;
    QTimer *connectionTimer;
    
    // Bağlantı bilgileri
    QString serverHost;
    int serverPort;
    ConnectionStatus connectionStatus;
    
    // C client connection
    client_connection_t *clientConnection;
    
    // ECDH context
    ecdh_context_t ecdhContext;
    bool ecdhInitialized;
    uint8_t aesKey[32];
    bool handshakeCompleted;
    
    // Thread safety
    QMutex connectionMutex;

    // TCP'den gelen verileri biriktirmek için buffer
    QByteArray incomingBuffer;

    // JWT token'ı saklamak için ek alan
    QString jwtToken;

    ConnectionType currentType = ConnectionType::TCP;
    QTcpSocket* p2pSocket = nullptr;

    // Yardımcı fonksiyonlar
    void initializeConnection();
    void cleanupConnection();
    void setupSignals();
    void initializeECDHHandshake();
    void processECDHResponse(const QByteArray& data);
    void sendJsonString(const QString& jsonString, bool encrypted);
    void logInfo(const QString& message);
    void logError(const QString& message);
    void logDebug(const QString& message);

    // AES256 CBC çözme fonksiyonu prototipi
    QByteArray decryptAes256Cbc(const QByteArray &cipher, const QByteArray &key, const QByteArray &iv);
};

#endif // CLIENT_WRAPPER_H
