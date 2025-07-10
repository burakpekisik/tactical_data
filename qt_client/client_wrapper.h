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
    // === CHAT ROOM JOIN ===
    // Odaya katılma isteği gönderir
    Q_INVOKABLE void joinChatRoom(int roomId);
    // Oda anahtarını alır (asenkron)
    Q_INVOKABLE void fetchRoomKey(int roomId, const QString& jwtToken);
    // Chat mesajlarını getirir (asenkron)
    Q_INVOKABLE void fetchChatMessages(int roomId, const QByteArray& roomKey);

    // --- Admin bildirim dinleme ---
    void listenForAdminNotifications();
    bool testAllConnectionTypes(const QString& jsonString, bool encrypted);
    void queryRepliesForReport(int reportId);
    void sendSelectLatestLocationsAllUsers();
    // --- Normal kullanıcılar için birimin son konumları ---
    void sendSelectLatestLocationsByCurrentUnit();

    void requestChatRoomList();
    void createChatRoom(const QString& roomName, int accessType, int maxUsers, const QString& allowedUserIds);

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
    client_connection_t* getClientConnection() const { return clientConnection; }

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

    /**
     * @brief Konum bilgisini sunucuya gönderir (taktik veri gibi, JSON ile)
     * @param latitude Enlem
     * @param longitude Boylam
     * @param timestamp Unix zaman damgası
     * @param description Açıklama (opsiyonel)
     * @param encrypted Şifreli gönderim
     */
    void sendLocation(double latitude, double longitude, long timestamp, const QString& description = QString(), bool encrypted = true);
    /**
     * @brief Konum JSON'unu uygun protokol ile gönderir
     * @param jsonString JSON verisi
     * @param encrypted Şifreli gönderim
     */
    void sendLocationJson(const QString& jsonString, bool encrypted = true);

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

    // --- Admin fonksiyonları ---
    void adminReplyToReport(int reportId, const QString& message);
    void queryMyReplies();
    void watchReportReplies();
    void sendAllPendingAdminReplies();

private:
    // --- Bağlantı türü kontrolü ---
    void switchConnectionType(ConnectionType type);
    QString getConnectionTypeString() const;
    
    // --- Fallback test fonksiyonları ---
    bool testUdpConnection();
    bool testP2pConnection();


    // --- Gelişmiş bağlantı test fonksiyonları ---
    // bool testAllConnectionTypes(const QString& jsonString, bool encrypted); // Artık public
    bool connectToServerInternal(const QString& host, int port, ConnectionType type);
    void handleAdvancedError(const QString& error, bool canFallback);

    // --- Admin reply yardımcı fonksiyonları ---
    bool trySendAdminReplyInternal(int reportId, const QString& message);
    void saveAdminReplyToPending(int reportId, const QString& message);

    // --- Rapor reply sorgulama ---
    // void queryRepliesForReport(int reportId); // Artık public

signals:
    // Odaya katılım başarılı/başarısız olduğunda
    void joinRoomSuccess(int roomId);
    void joinRoomFailed(int roomId, const QString& error);
    // Oda anahtarı alındığında/başarısız olduğunda
    void roomKeyReceived(int roomId, const QByteArray& key);
    void roomKeyFailed(int roomId, const QString& error);
    void chatRoomListReceived(const QJsonArray& rooms);
    // Chat mesajları başarıyla alındığında
    void chatMessagesReceived(int roomId, const QJsonArray& messages);
    void chatMessagesFailed(int roomId, const QString& error);

    /**
     * @brief Tüm kullanıcıların son konumları alındığında emit edilir
     * @param locations QJsonArray (her biri: user_id, latitude, longitude, timestamp, description)
     */
    void allUsersLatestLocationsReceived(const QJsonArray& locations);
    /**
     * @brief Normal kullanıcılar için birimin son konumları alındığında emit edilir
     * @param locations QJsonArray (her biri: user_id, latitude, longitude, timestamp, description)
     */
    void myUnitLatestLocationsReceived(const QJsonArray& locations);
    /**
     * @brief Admin bildirimi alındığında emit edilir
     * @param notification Bildirim mesajı
     */
    void adminNotificationReceived(const QString& notification);
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
     * @param privilege Kullanıcı yetkisi (0: normal, 1: admin)
     */
    void reportsReceived(const QJsonArray& reports, int privilege);

    /**
     * @brief ECDH tamamlandığında emit edilir
     */
    void ecdhHandshakeCompleted(); // <-- ECDH tamamlandığında tetiklenecek sinyal

    /**
     * @brief Reply sorgu sonucu alındığında emit edilir
     * @param replies Cevap listesi
     */
    void replyQueryResultReceived(const QJsonArray& replies);

    /**
     * @brief Fallback test sonucu emit edilir
     * @param connectionType Bağlantı türü
     * @param success Başarı durumu
     * @param message Test mesajı
     */
    void fallbackTestResult(const QString& connectionType, bool success, const QString& message);

    /**
     * @brief Bağlantı türü değiştiğinde emit edilir
     * @param type Yeni bağlantı türü
     */
    void connectionTypeChanged(ConnectionType type);

    /**
     * @brief Fallback durumu değiştiğinde emit edilir
     * @param status Durum mesajı
     */
    void fallbackStatusChanged(const QString& status);

    /**
     * @brief Admin reply sonucu signal'ları
     */
    void dataSuccess(const QString& message);
    void dataInfo(const QString& message);
    void dataError(const QString& message);

    /**
     * @brief Belirli bir rapor için admin reply'ları alındığında emit edilir
     * @param reportId Rapor ID'si
     * @param replies Cevap listesi
     */
    void reportRepliesReceived(int reportId, const QJsonArray& replies);
    
    /**
     * @brief Yeni bir rapor cevabı alındığında emit edilir
     * @param reportId Rapor ID'si
     * @param message Cevap mesajı
     */
    void newReportReplyReceived(int reportId, const QString& message);

private slots:
    void onSocketConnected();
    void onSocketDisconnected();
    void onSocketError();
    void onDataReceived();
    void onConnectionTimeout();
    // Admin bildirim dinleme için slot

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

    // Parçalı yanıt işleme için değişkenler
    QByteArray allHexData;
    QByteArray allPlainData;
    int expectedParts = 0;
    int receivedParts = 0;
    bool isProcessingParts = false;

    // Retry mekanizması için değişkenler
    static const int MAX_RETRY_COUNT = 4;  // Her metod için maksimum 4 retry
    int tcpRetryCount = 0;
    int udpRetryCount = 0;
    int p2pRetryCount = 0;
    QString lastJsonData;  // Son gönderilmeye çalışılan veri
    bool lastEncryptionFlag = false;  // Son şifreleme durumu

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
    
    // Parçalı yanıt işleme fonksiyonları
    void processEncryptedParts();
    void processEncryptedResponse();
    void resetPartProcessing();
    void finalizePartProcessing();
    
    // Retry mekanizması fonksiyonları
    void retryWithFallback(const QString& jsonData, bool encrypted);
    void resetRetryCounters();
    bool tryNextConnectionType(const QString& jsonData, bool encrypted);
    void handleConnectionFailure(ConnectionType failedType, const QString& error);
};

#endif // CLIENT_WRAPPER_H
