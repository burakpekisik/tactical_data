/**
 * @file client_wrapper.cpp
 * @brief Qt Client wrapper sınıfının implementasyonu
 * @details C client kodları ile Qt GUI arasında köprü görevi görür.
 *          TCP bağlantı yönetimi, veri gönderimi ve şifreleme işlemlerini sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 */

#include "client_wrapper.h"
#include <QHostAddress>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QTextStream>
#include <QCoreApplication>
#include <QDir>
#include <QDebug>
#include <QJsonArray>
extern "C" {
    #include "encrypted_client.h"
    #include "crypto_utils.h"
    #include "protocol_manager.h"
    #include "fallback_manager.h"
    #include "config.h"
    #include "logger.h"
    #include "cJSON.h"
    #include "chat_protocol.h"
}

QByteArray decryptAes256Cbc(const QByteArray &cipher, const QByteArray &key, const QByteArray &iv);


ClientWrapper::ClientWrapper(QObject *parent)
    : QObject(parent)
    , tcpSocket(nullptr)
    , udpSocket(nullptr)
    , connectionTimer(nullptr)
    , serverHost("127.0.0.1")
    , serverPort(8080)
    , connectionStatus(Disconnected)
    , clientConnection(nullptr)
    , ecdhInitialized(false)
    , handshakeCompleted(false)
    , jwtToken("")
    , expectedParts(0)
    , receivedParts(0)
    , isProcessingParts(false)
    , tcpRetryCount(0)
    , udpRetryCount(0)
    , p2pRetryCount(0)
{
    // ECDH context'i sıfırla
    memset(&ecdhContext, 0, sizeof(ecdh_context_t));
    memset(aesKey, 0, sizeof(aesKey));
    
    initializeConnection();
    setupSignals();
    
    // Ana proje dizinine geç (logger için)
    QString originalDir = QDir::currentPath();
    QString projectDir = QDir(originalDir).absoluteFilePath("../..");
    QDir::setCurrent(projectDir);
    
    // Logger'ı başlat
    if (logger_init(LOGGER_CLIENT, LOG_DEBUG) != 0) {
        logError("Logger başlatılamadı!");
        // Working directory'yi geri al
        QDir::setCurrent(originalDir);
    } else {
        LOG_CLIENT_INFO("Qt Client wrapper initialized");
        logInfo("Qt Client wrapper initialized");
        // Working directory'yi geri al
        QDir::setCurrent(originalDir);
    }
}

/**
 * @brief ClientWrapper destructor'ı
 */
ClientWrapper::~ClientWrapper()
{
    cleanupConnection();
    logger_cleanup(LOGGER_CLIENT);
}

/**
 * @brief Bağlantı bileşenlerini başlatır
 */
void ClientWrapper::initializeConnection()
{
    // TCP socket oluştur
    tcpSocket = new QTcpSocket(this);
    
    // UDP socket oluştur (gelecekte kullanım için)
    udpSocket = new QUdpSocket(this);
    
    // Connection timeout timer
    connectionTimer = new QTimer(this);
    connectionTimer->setSingleShot(true);
    connectionTimer->setInterval(10000); // 10 saniye timeout
}

/**
 * @brief Signal-slot bağlantılarını kurar
 */
void ClientWrapper::setupSignals()
{
    // TCP socket signals
    connect(tcpSocket, &QTcpSocket::connected, this, &ClientWrapper::onSocketConnected);
    connect(tcpSocket, &QTcpSocket::disconnected, this, &ClientWrapper::onSocketDisconnected);
    connect(tcpSocket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &ClientWrapper::onSocketError);
    connect(tcpSocket, &QTcpSocket::readyRead, this, &ClientWrapper::onDataReceived);
    
    // Connection timer
    connect(connectionTimer, &QTimer::timeout, this, &ClientWrapper::onConnectionTimeout);
}

/**
 * @brief Mevcut bağlantı durumunu döner
 * @return ConnectionStatus Bağlantı durumu
 */
ClientWrapper::ConnectionStatus ClientWrapper::getConnectionStatus() const
{
    return connectionStatus;
}

/**
 * @brief Bağlı olup olmadığını kontrol eder
 * @return bool Bağlantı durumu
 */
bool ClientWrapper::isConnected() const
{
    // Hem enum değerini hem de gerçek socket durumunu kontrol et
    if (connectionStatus != Connected) {
        return false;
    }
    
    // TCP socket'in gerçek durumunu kontrol et
    if (!tcpSocket) {
        return false;
    }
    
    // Socket bağlı değilse enum'u da güncelle
    if (tcpSocket->state() != QAbstractSocket::ConnectedState) {
        // Const metod olduğu için mutable ile değiştirme yapmak yerine
        // sadece false döndür, durumu başka yerden güncelleriz
        return false;
    }
    
    return true;
}

/**
 * @brief Sunucuya bağlantı kurar
 * @param host Sunucu IP adresi
 * @param port Sunucu port numarası
 */
void ClientWrapper::connectToServer(const QString& host, int port)
{
    QMutexLocker locker(&connectionMutex);
    
    if (connectionStatus == Connected || connectionStatus == Connecting) {
        PRINTF_LOG("Already connected or connecting to server\n");
        logInfo("Already connected or connecting to server");
        return;
    }
    
    serverHost = host;
    serverPort = port;
    connectionStatus = Connecting;
    
    PRINTF_LOG("Attempting to connect to %s:%d\n", host.toUtf8().constData(), port);
    logInfo(QString("Attempting to connect to %1:%2").arg(host).arg(port));
    emit connectionStatusChanged(Connecting, "Sunucuya bağlanılıyor...");
    
    // TCP bağlantısı kur
    tcpSocket->connectToHost(QHostAddress(host), static_cast<quint16>(port));
    connectionTimer->start();
}

/**
 * @brief Sunucu bağlantısını keser
 */
void ClientWrapper::disconnectFromServer()
{
    QMutexLocker locker(&connectionMutex);
    
    if (connectionStatus == Disconnected) {
        return;
    }
    
    PRINTF_LOG("Disconnecting from server\n");
    LOG_CLIENT_INFO("User requested disconnect from server");
    logInfo("Disconnecting from server");
    connectionTimer->stop();
    
    if (tcpSocket->state() != QAbstractSocket::UnconnectedState) {
        tcpSocket->disconnectFromHost();
        if (tcpSocket->state() != QAbstractSocket::UnconnectedState) {
            tcpSocket->waitForDisconnected(3000);
        }
    }
    
    cleanupConnection();
    connectionStatus = Disconnected;
    emit connectionStatusChanged(Disconnected, "Bağlantı kesildi");
}

/**
 * @brief Socket bağlantısı kurulduğunda çağrılır
 */
void ClientWrapper::onSocketConnected()
{
    QMutexLocker locker(&connectionMutex);
    connectionTimer->stop();
    connectionStatus = Connected;
    PRINTF_LOG("✓ Connected to server %s:%d\n", serverHost.toUtf8().constData(), serverPort);
    LOG_CLIENT_INFO("Successfully connected to server %s:%d", serverHost.toUtf8().constData(), serverPort);
    logInfo(QString("Connected to server %1:%2").arg(serverHost).arg(serverPort));
    qDebug() << "[DEBUG] onSocketConnected, jwtToken:" << jwtToken;
    // ECDH anahtar değişimini başlat
    initializeECDHHandshake();
    // --- ECDH ve AES anahtarlarını logla ---
    qDebug() << "[DEBUG] ECDH public_key:" << QByteArray((const char*)ecdhContext.public_key, ECC_PUB_KEY_SIZE).toHex();
    qDebug() << "[DEBUG] ECDH shared_secret:" << QByteArray((const char*)ecdhContext.shared_secret, 32).toHex();
    qDebug() << "[DEBUG] AES anahtarı (aesKey):" << QByteArray((const char*)aesKey, 32).toHex();
    emit connectionStatusChanged(Connected, "Sunucuya bağlandı");
}

/**
 * @brief Socket bağlantısı kesildiğinde çağrılır
 */
void ClientWrapper::onSocketDisconnected()
{
    QMutexLocker locker(&connectionMutex);
    connectionTimer->stop();
    if (connectionStatus != Disconnected) {
        connectionStatus = Disconnected;
        PRINTF_LOG("✗ Disconnected from server\n");
        LOG_CLIENT_INFO("Connection to server was lost");
        logInfo("Disconnected from server");
        qDebug() << "[DEBUG] onSocketDisconnected, jwtToken:" << jwtToken;
        emit connectionStatusChanged(Disconnected, "Sunucu bağlantısı kesildi");
    }
}

/**
 * @brief Socket hatası oluştuğunda çağrılır
 */
void ClientWrapper::onSocketError()
{
    QMutexLocker locker(&connectionMutex);
    connectionTimer->stop();
    
    QString errorString = tcpSocket->errorString();
    connectionStatus = Error;
    
    logError(QString("Socket error: %1").arg(errorString));
    emit connectionStatusChanged(Error, QString("Bağlantı hatası: %1").arg(errorString));
}

/**
 * @brief Bağlantı timeout'u oluştuğunda çağrılır
 */
void ClientWrapper::onConnectionTimeout()
{
    QMutexLocker locker(&connectionMutex);
    
    if (connectionStatus == Connecting) {
        tcpSocket->abort();
        connectionStatus = Error;
        logError("Connection timeout");
        emit connectionStatusChanged(Error, "Bağlantı zaman aşımı");
    }
}

/**
 * @brief Sunucudan veri alındığında çağrılır
 */
void ClientWrapper::onDataReceived()
{
    QByteArray data = tcpSocket->readAll();
    incomingBuffer.append(data);
    PRINTF_LOG("Raw data received (%d bytes)\n", data.size());
    LOG_CLIENT_DEBUG("Received raw data from server: %d bytes", data.size());
    qDebug() << "[DEBUG] onDataReceived, jwtToken:" << jwtToken;
    qDebug() << "[DEBUG] incomingBuffer (ilk 200):" << QString(incomingBuffer.left(200));

    // ECDH handshake response'unu kontrol et (server public key)
    if (!handshakeCompleted && incomingBuffer.size() >= ECC_PUB_KEY_SIZE) {
        QByteArray pubKey = incomingBuffer.left(ECC_PUB_KEY_SIZE);
        incomingBuffer.remove(0, ECC_PUB_KEY_SIZE);
        PRINTF_LOG("Received server public key (%d bytes)\n", pubKey.size());
        LOG_CLIENT_INFO("Processing server public key for ECDH handshake");
        processECDHResponse(pubKey);
        return;
    }

    // onDataReceived içinde:
    QJsonDocument doc = QJsonDocument::fromJson(incomingBuffer);
    if (doc.isObject()) {
        QJsonObject obj = doc.object();
        if (obj.contains("rooms")) {
            QJsonArray rooms = obj["rooms"].toArray();
            logInfo("[CHAT] Chat odası listesi yanıtı alındı. Oda sayısı: " + QString::number(rooms.size()));
            logInfo("[CHAT] Chat odası listesi JSON: " + QString::fromUtf8(QJsonDocument(rooms).toJson(QJsonDocument::Compact)));
            emit chatRoomListReceived(rooms);
        }
    }

    // --- Parçalı ENCRYPTED_PART yanıtları işle ---
    processEncryptedParts();

    // --- Tek parçalı ENCRYPTED yanıtları işle ---
    processEncryptedResponse();

    // --- JSON biriktirme ve admin notification detection ---
    QString bufferStr = QString::fromUtf8(incomingBuffer);
    
    // Eğer buffer JSON içeriyorsa onu extract et
    int jsonStart = bufferStr.indexOf('{');
    if (jsonStart != -1) {
        // JSON başlangıcı bulundu, sonu var mı?
        int jsonEnd = bufferStr.lastIndexOf('}');
        if (jsonEnd > jsonStart) {
            // Tam JSON var
            QString jsonStr = bufferStr.mid(jsonStart, jsonEnd - jsonStart + 1);
            qDebug() << "[DEBUG] Complete JSON extracted:" << jsonStr.left(200);
        }
    }
    
    // --- Düz metin/legacy mesajları ayıkla ---
    // Notification JSON'u için buffer
    static QString notificationBuffer;
    while (!incomingBuffer.isEmpty()) {
        int plainEnd = incomingBuffer.indexOf('\n');
        if (plainEnd == -1) break; // Satır sonu yoksa bekle

        QByteArray plainMsg = incomingBuffer.left(plainEnd);
        incomingBuffer.remove(0, plainEnd + 1);

        QString msgStr = QString::fromUtf8(plainMsg);
        if (!msgStr.startsWith("ENCRYPTED") && !msgStr.isEmpty()) {
            qDebug() << "[DEBUG] Plain/legacy data received:" << msgStr.left(200);

            // --- ADMIN_NOTIFY ve REPORT_REPLY mesajlarını işle ---
            int adminPos = msgStr.indexOf("ADMIN_NOTIFY:");
            int replyPos = msgStr.indexOf("REPORT_REPLY:");
            if (adminPos > 0) {
                QString normalMsg = msgStr.left(adminPos);
                emit dataReceived(normalMsg);
                QString notifyMsg = msgStr.mid(adminPos);
                if (notifyMsg.startsWith("ADMIN_NOTIFY:")) {
                    qDebug() << "[DEBUG] Admin notify extracted from combined message:" << notifyMsg;
                    QString notification = notifyMsg.mid(13);
                    emit adminNotificationReceived(notification);
                }
                continue;
            } else if (msgStr.startsWith("ADMIN_NOTIFY:")) {
                qDebug() << "[DEBUG] Admin notify detected:" << msgStr;
                QString notification = msgStr.mid(13);
                emit adminNotificationReceived(notification);
                continue;
            } else if (replyPos > 0) {
                QString normalMsg = msgStr.left(replyPos);
                emit dataReceived(normalMsg);
                QString replyMsg = msgStr.mid(replyPos);
                if (replyMsg.startsWith("REPORT_REPLY:")) {
                    qDebug() << "[DEBUG] Report reply extracted from combined message:" << replyMsg;
                    QString content = replyMsg.mid(13);
                    int reportId = content.section(':', 0, 0).toInt();
                    QString message = content.section(':', 1);
                    qDebug() << "[DEBUG] Extracted reportId:" << reportId << ", message:" << message;
                    emit newReportReplyReceived(reportId, message);
                }
                continue;
            } else if (msgStr.startsWith("REPORT_REPLY:")) {
                qDebug() << "[DEBUG] Report reply detected:" << msgStr;
                QString content = msgStr.mid(13);
                int reportId = content.section(':', 0, 0).toInt();
                QString message = content.section(':', 1);
                emit newReportReplyReceived(reportId, message);
                continue;
            } else if (msgStr.startsWith("REPORT_REPLY_PONG")) {
                qDebug() << "[DEBUG] Report reply keepalive response received";
                continue;
            }

            // JSON notification biriktirme
            if (msgStr.startsWith("{") || !notificationBuffer.isEmpty()) {
                notificationBuffer += msgStr;
                // Her satırdan sonra yeni satır ekle (görsellik için, JSON bozulmaz)
                if (!msgStr.endsWith("}"))
                    notificationBuffer += "\n";
            }

            // Her yeni satırda buffer'ı JSON olarak parse etmeyi dene
            if (!notificationBuffer.isEmpty() && notificationBuffer.trimmed().startsWith("{") && notificationBuffer.trimmed().endsWith("}")) {
                QJsonParseError parseError;
                QJsonDocument doc = QJsonDocument::fromJson(notificationBuffer.toUtf8(), &parseError);
                if (parseError.error == QJsonParseError::NoError) {
                    QJsonObject obj = doc.object();
                    // Sadece notification ise göster (user_id, status, description varsa)
                    if (obj.contains("user_id") || obj.contains("status") || obj.contains("description")) {
                        emit adminNotificationReceived(notificationBuffer);
                        qDebug() << "[DEBUG] Notification JSON detected and emitted.";
                        notificationBuffer.clear();
                        continue;
                    }
                }
                // Parse başarısızsa buffer'ı temizleme, yeni satır gelmesini bekle
            }

            // JSON parçası değilse normal data olarak emit et
            if (!msgStr.startsWith("{") && !msgStr.startsWith("\t")) {
                emit dataReceived(msgStr);
            }
        }
    }
    // Tüm işlemlerden sonra buffer'da işlenemeyen veri kaldıysa temizle
    if (!incomingBuffer.isEmpty()) {
        qDebug() << "[DEBUG] incomingBuffer temizleniyor (işlenemeyen veri):" << QString(incomingBuffer.left(200));
        incomingBuffer.clear();
    }
}

/**
 * @brief Sunucya uygun JSON'u oluşturur
 * @param latitude Enlem
 * @param longitude Boylam
 * @param dataType Veri tipi
 * @param message Mesaj
 * @return QString JSON string
 */
QString ClientWrapper::createTacticalDataJson(double latitude, double longitude, 
                                            const QString& dataType, const QString& message)
{
    QJsonObject jsonObj;
    // jsonObj["unit_id"] = "BİRİM-01";
    
    jsonObj["status"] = dataType;
    jsonObj["latitude"] = latitude;
    jsonObj["longitude"] = longitude;
    jsonObj["description"] = message.isEmpty() ? "Qt Client'tan gönderildi" : message;
    jsonObj["timestamp"] = QDateTime::currentSecsSinceEpoch();
    
    QJsonDocument jsonDoc(jsonObj);
    return jsonDoc.toJson(QJsonDocument::Compact);
}

/**
 * @brief Taktik veri gönderir
 * @param latitude Enlem koordinatı
 * @param longitude Boylam koordinatı
 * @param dataType Veri tipi
 * @param message Kullanıcı mesajı
 * @param encrypted Şifreli gönderim
 */
void ClientWrapper::sendTacticalData(double latitude, double longitude, 
                                   const QString& dataType, const QString& message, 
                                   bool encrypted)
{
    if (!isConnected()) {
        PRINTF_LOG("✗ Not connected to server - cannot send data\n");
        LOG_CLIENT_ERROR("Attempted to send data while not connected");
        emit dataSendResult(NotConnected, "Sunucuya bağlı değilsiniz");
        return;
    }
    
    PRINTF_LOG("Preparing tactical data: lat=%.6f, lon=%.6f, type=%s, encrypted=%s\n", 
               latitude, longitude, dataType.toUtf8().constData(), encrypted ? "yes" : "no");
    LOG_CLIENT_INFO("Sending tactical data: lat=%.6f, lon=%.6f, type=%s", 
                    latitude, longitude, dataType.toUtf8().constData());
    
    QString jsonString = createTacticalDataJson(latitude, longitude, dataType, message);
    sendJsonString(jsonString, encrypted);
}

/**
 * @brief JSON string gönderir
 * @param jsonString JSON verisi
 * @param encrypted Şifreli gönderim seçeneği
 */
void ClientWrapper::sendJsonString(const QString& jsonString, bool encrypted)
{
    qDebug() << "[DEBUG] sendJsonString çağrıldı, jwtToken:" << jwtToken << ", handshakeCompleted:" << handshakeCompleted;
    PRINTF_LOG("[CLIENT][SEND] sendJsonString çağrıldı, jwtToken=%s, handshakeCompleted=%d\n", jwtToken.toUtf8().constData(), handshakeCompleted);
    logDebug(QString("sendJsonString çağrıldı, jwtToken=%1, handshakeCompleted=%2").arg(jwtToken).arg(handshakeCompleted));

    // Son gönderilecek veriyi kaydet (retry için)
    lastJsonData = jsonString;
    lastEncryptionFlag = encrypted;

    // Bağlantı durumunu kontrol et ve gerekirse güncelle
    if (!isConnected()) {
        if (tcpSocket && tcpSocket->state() != QAbstractSocket::ConnectedState) {
            connectionStatus = Disconnected;
            emit connectionStatusChanged(Disconnected, "Bağlantı kesildiği tespit edildi");
        }
        PRINTF_LOG("[CLIENT][SEND][ERROR] Not connected, JSON gönderilemiyor\n");
        logError("Not connected, JSON gönderilemiyor");
        retryWithFallback(jsonString, encrypted);
        return;
    }
    if (encrypted && !handshakeCompleted) {
        PRINTF_LOG("[CLIENT][SEND][ERROR] ECDH handshake tamamlanmamış, şifreli veri gönderilemez\n");
        logError("ECDH handshake tamamlanmamış, şifreli veri gönderilemez");
        retryWithFallback(jsonString, encrypted);
        return;
    }
    qDebug() << "[DEBUG] sendJsonString, aesKey (ilk 8):" << QByteArray((const char*)aesKey, 8).toHex();
    PRINTF_LOG("[CLIENT][SEND] aesKey (ilk 8): %s\n", QByteArray((const char*)aesKey, 8).toHex().constData());
    try {
        sendAllPendingJson(encrypted);

        if (!isConnected()) {
            PRINTF_LOG("[CLIENT][SEND][ERROR] Bağlantı koptu, retry başlatılıyor\n");
            logError("Bağlantı koptu, retry başlatılıyor");
            retryWithFallback(jsonString, encrypted);
            return;
        }

        char* protocolMessage = nullptr;
        if (encrypted) {
            PRINTF_LOG("[CLIENT][SEND] Creating encrypted protocol message...\n");
            LOG_CLIENT_INFO("Preparing encrypted JSON transmission");
            qDebug() << "[DEBUG] create_encrypted_protocol_message jwtToken:" << jwtToken;
            protocolMessage = create_encrypted_protocol_message("tactical_data.json", 
                                                               jsonString.toUtf8().constData(), 
                                                               aesKey, 
                                                               jwtToken.toUtf8().constData());
        } else {
            PRINTF_LOG("[CLIENT][SEND] Creating normal protocol message...\n");
            LOG_CLIENT_INFO("Preparing normal JSON transmission");
            qDebug() << "[DEBUG] create_normal_protocol_message jwtToken:" << jwtToken;
            protocolMessage = create_normal_protocol_message("tactical_data.json", 
                                                            jsonString.toUtf8().constData(), 
                                                            jwtToken.toUtf8().constData());
        }
        if (protocolMessage == nullptr) {
            PRINTF_LOG("[CLIENT][SEND][ERROR] Protocol message oluşturulamadı\n");
            LOG_CLIENT_ERROR("Failed to create protocol message");
            logError("Protocol message oluşturulamadı");
            retryWithFallback(jsonString, encrypted);
            return;
        }

        QByteArray messageData(protocolMessage, strlen(protocolMessage));
        PRINTF_LOG("[CLIENT][SEND] Sending protocol message (%d bytes): %.50s...\n", 
                   messageData.size(), protocolMessage);
        LOG_CLIENT_INFO("Transmitting protocol message to server (%d bytes)", messageData.size());
        qDebug() << "[DEBUG] tcpSocket->state():" << tcpSocket->state();

        qint64 bytesWritten = tcpSocket->write(messageData);
        PRINTF_LOG("[CLIENT][SEND] tcpSocket->write() döndü: %lld\n", bytesWritten);
        if (bytesWritten == -1) {
            PRINTF_LOG("[CLIENT][SEND][ERROR] Protocol message gönderilemedi, tcpSocket error: %s\n", tcpSocket->errorString().toUtf8().constData());
            LOG_CLIENT_ERROR("Failed to send protocol message");
            logError(QString("tcpSocket->write() error: %1").arg(tcpSocket->errorString()));
            free(protocolMessage);
            retryWithFallback(jsonString, encrypted);
            return;
        } else {
            tcpSocket->flush();
            PRINTF_LOG("[CLIENT][SEND] Protocol message sent successfully (%lld bytes)\n", bytesWritten);
            LOG_CLIENT_INFO("Protocol message transmitted successfully: %lld bytes", bytesWritten);
            logInfo(QString("Protocol message sent successfully (%1 bytes)").arg(bytesWritten));
            resetRetryCounters();
            emit dataSendResult(SendSuccess, 
                encrypted ? "Şifreli veri başarıyla gönderildi" : "Veri başarıyla gönderildi");
        }
        free(protocolMessage);
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Exception in sendJsonString: %s", e.what());
        logError(QString("Exception in sendJsonString: %1").arg(e.what()));
        retryWithFallback(jsonString, encrypted);
    }
}

/**
 * @brief JSON dosya gönderir
 * @param filePath Dosya yolu
 * @param encrypted Şifreli gönderim
 */
void ClientWrapper::sendJsonFile(const QString& filePath, bool encrypted)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit dataSendResult(InvalidData, "Dosya açılamadı: " + filePath);
        return;
    }
    
    QTextStream stream(&file);
    QString jsonContent = stream.readAll();
    file.close();
    
    sendJsonString(jsonContent, encrypted);
}

/**
 * @brief Bağlantı kaynaklarını temizler
 */
void ClientWrapper::cleanupConnection()
{
    if (clientConnection) {
        // C connection cleanup if needed
        clientConnection = nullptr;
    }
}

/**
 * @brief Info log mesajı
 */
void ClientWrapper::logInfo(const QString& message)
{
    LOG_CLIENT_INFO(message.toUtf8().constData());
    PRINTF_CLIENT("INFO: %s\n", message.toUtf8().constData());
    qDebug() << "[INFO]" << message;
    emit logMessage(message);
}

/**
 * @brief Error log mesajı
 */
void ClientWrapper::logError(const QString& message)
{
    LOG_CLIENT_ERROR(message.toUtf8().constData());
    PRINTF_CLIENT("ERROR: %s\n", message.toUtf8().constData());
    qDebug() << "[ERROR]" << message;
    emit logMessage(message);
}

/**
 * @brief Debug log mesajı
 */
void ClientWrapper::logDebug(const QString& message)
{
    PRINTF_CLIENT("DEBUG: %s\n", message.toUtf8().constData());
    qDebug() << "[DEBUG]" << message;
    emit logMessage(message);
}

/**
 * @brief ECDH anahtar değişimini başlatır
 */
void ClientWrapper::initializeECDHHandshake()
{
    PRINTF_LOG("Starting ECDH handshake...\n");
    LOG_CLIENT_INFO("Initializing ECDH handshake");
    
    // ECDH context'i initialize et
    if (ecdh_init_context(&ecdhContext) == 0) {
        LOG_CLIENT_ERROR("Failed to initialize ECDH context");
        logError("ECDH context başlatılamadı");
        return;
    }
    
    // ECDH key pair oluştur
    if (ecdh_generate_keypair(&ecdhContext) == 0) {
        LOG_CLIENT_ERROR("Failed to generate ECDH key pair");
        logError("ECDH anahtar çifti oluşturulamadı");
        return;
    }
    
    ecdhInitialized = true;
    LOG_CLIENT_INFO("ECDH key pair generated successfully");
    PRINTF_LOG("✓ ECDH key pair generated\n");
    logInfo("ECDH anahtar çifti başarıyla oluşturuldu");
    
    // Public key'i sunucuya gönder (raw binary olarak)
    QByteArray publicKeyData(reinterpret_cast<const char*>(ecdhContext.public_key), ECC_PUB_KEY_SIZE);
    PRINTF_LOG("Sending public key (%d bytes)\n", ECC_PUB_KEY_SIZE);
    LOG_CLIENT_INFO("Sending ECDH public key to server");
    qint64 bytesWritten = tcpSocket->write(publicKeyData);
    if (bytesWritten != ECC_PUB_KEY_SIZE) {
        LOG_CLIENT_ERROR("Failed to send complete public key");
        logError("Public key gönderimi başarısız");
        return;
    }
    tcpSocket->flush();
    PRINTF_LOG("✓ Public key sent successfully (%lld bytes)\n", bytesWritten);
    logInfo("Public key başarıyla gönderildi");
}

/**
 * @brief ECDH response'unu işler
 */
void ClientWrapper::processECDHResponse(const QByteArray& data)
{
    // Server public key'i doğrudan raw binary olarak al
    if (data.size() != ECC_PUB_KEY_SIZE) {
        LOG_CLIENT_ERROR("Invalid server public key size: %d", data.size());
        logError("Sunucu public key boyutu geçersiz");
        return;
    }
    
    PRINTF_LOG("Processing server public key (%d bytes)\n", data.size());
    LOG_CLIENT_INFO("Computing shared secret");
    
    // Shared secret hesapla
    if (ecdh_compute_shared_secret(&ecdhContext, 
                                  reinterpret_cast<const uint8_t*>(data.constData())) == 0) {
        LOG_CLIENT_ERROR("Failed to compute shared secret");
        logError("Shared secret hesaplanamadı");
        return;
    }
    
    // AES anahtarını türet
    if (ecdh_derive_aes_key(&ecdhContext) == 0) {
        LOG_CLIENT_ERROR("Failed to derive AES key");
        logError("AES anahtar türetme hatası");
        return;
    }
    
    // Türetilen AES anahtarını al (context içinden)
    memcpy(aesKey, ecdhContext.aes_key, 32);
    
    handshakeCompleted = true;
    LOG_CLIENT_INFO("ECDH handshake completed successfully");
    PRINTF_LOG("✓ ECDH handshake completed\n");
    logInfo("ECDH anahtar değişimi tamamlandı");
    emit ecdhHandshakeCompleted(); // <-- ECDH tamamlanınca sinyal gönder
    
    // Console client protokolünde ACK mesajı yok, handshake bu noktada tamamlanır
    PRINTF_LOG("✓ ECDH protocol completed, ready for encrypted communication\n");
}

// --- Pending JSON gönderimlerini yönet ---
void ClientWrapper::sendAllPendingJson(bool encrypted) {
    QDir pendingDir(QCoreApplication::applicationDirPath() + "/pending");
    if (!pendingDir.exists()) return;
    QStringList files = pendingDir.entryList(QStringList() << "*.json", QDir::Files, QDir::Name);
    for (const QString& file : files) {
        QFile f(pendingDir.filePath(file));
        if (f.open(QIODevice::ReadOnly)) {
            QString jsonContent = QTextStream(&f).readAll();
            f.close();
            bool success = trySendJsonInternal(jsonContent, encrypted);
            if (success) f.remove();
            else break; // Bağlantı yoksa veya hata varsa kalanları deneme
        }
    }
}

// --- JSON gönderimini dener, başarılıysa true döner ---
bool ClientWrapper::trySendJsonInternal(const QString& jsonString, bool encrypted) {
    if (!isConnected()) return false;
    // Eğer düz PING komutu ise, protokol sarmalamasına sokmadan gönder
    if (jsonString.trimmed() == "PING") {
        QByteArray pingData = "PING";
        qint64 bytesWritten = tcpSocket->write(pingData);
        tcpSocket->flush();
        return (bytesWritten > 0);
    }
    char* protocolMessage = nullptr;
    if (encrypted) {
        protocolMessage = create_encrypted_protocol_message("tactical_data.json", jsonString.toUtf8().constData(), aesKey, jwtToken.toUtf8().constData());
    } else {
        protocolMessage = create_normal_protocol_message("tactical_data.json", jsonString.toUtf8().constData(), jwtToken.toUtf8().constData());
    }
    if (!protocolMessage) return false;
    QByteArray messageData(protocolMessage, strlen(protocolMessage));
    qint64 bytesWritten = tcpSocket->write(messageData);
    tcpSocket->flush();
    free(protocolMessage);
    return (bytesWritten > 0);
}

bool ClientWrapper::connectUdp(const QString& host, int port) {
    if (!udpSocket) udpSocket = new QUdpSocket(this);
    return true;
}

bool ClientWrapper::udpEcdhHandshake(QByteArray& outAesKey) {
    ecdh_context_t udpEcdhCtx;
    memset(&udpEcdhCtx, 0, sizeof(ecdh_context_t));
    if (ecdh_init_context(&udpEcdhCtx) == 0) return false;
    if (ecdh_generate_keypair(&udpEcdhCtx) == 0) return false;

    QByteArray ecdhInitMsg = "ECDH_INIT";
    udpSocket->writeDatagram(ecdhInitMsg, QHostAddress(serverHost), serverPort + 1);

    QByteArray serverResponse;
    QHostAddress sender;
    quint16 senderPort;
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(udpSocket, &QUdpSocket::readyRead, &loop, &QEventLoop::quit);
    timer.start(2000);
    loop.exec();
    if (udpSocket->hasPendingDatagrams()) {
        serverResponse.resize(udpSocket->pendingDatagramSize());
        udpSocket->readDatagram(serverResponse.data(), serverResponse.size(), &sender, &senderPort);
    } else {
        return false;
    }
    if (!serverResponse.startsWith("ECDH_PUB:")) return false;

    QByteArray serverPubHex = serverResponse.mid(9);
    QByteArray serverPubBin = QByteArray::fromHex(serverPubHex);
    if (serverPubBin.size() != ECC_PUB_KEY_SIZE) return false;

    QByteArray clientPubMsg = "ECDH_PUB:" + QByteArray((const char*)udpEcdhCtx.public_key, ECC_PUB_KEY_SIZE).toHex();
    udpSocket->writeDatagram(clientPubMsg, QHostAddress(serverHost), serverPort + 1);

    if (ecdh_compute_shared_secret(&udpEcdhCtx, (const uint8_t*)serverPubBin.constData()) == 0) return false;
    if (ecdh_derive_aes_key(&udpEcdhCtx) == 0) return false;
    outAesKey = QByteArray((const char*)udpEcdhCtx.aes_key, 32);

    timer.start(2000);
    loop.exec();
    if (udpSocket->hasPendingDatagrams()) {
        QByteArray ack;
        ack.resize(udpSocket->pendingDatagramSize());
        udpSocket->readDatagram(ack.data(), ack.size());
        if (!ack.startsWith("ECDH_OK")) return false;
    } else {
        return false;
    }
    return true;
}

/**
 * @brief Fallback ile veri gönderimi dener
 * @param jsonString JSON verisi
 * @param encrypted Şifreli gönderim
 * @return bool Başarı durumu
 */
bool ClientWrapper::trySendWithFallback(const QString& jsonString, bool encrypted) {
    // 2. UDP ile gönderim dene
    if (connectUdp(serverHost, serverPort + 1)) {
        QByteArray udpAesKey;
        if (udpEcdhHandshake(udpAesKey)) {
            char* msg = create_encrypted_protocol_message("tactical_data.json", jsonString.toUtf8().constData(), (const uint8_t*)udpAesKey.constData(), jwtToken.toUtf8().constData());
            if (msg) {
                udpSocket->writeDatagram(QByteArray(msg, strlen(msg)), QHostAddress(serverHost), serverPort + 1);
                free(msg);
                logInfo("UDP ile veri gönderildi");
                emit dataSendResult(SendSuccess, "UDP ile veri gönderildi");
                return true;
            }
        }
    }
    // 3. P2P ile gönderim dene (TCP ile aynı akış, port 8082)
    if (connectP2p(serverHost, serverPort + 2)) {
        QByteArray p2pAesKey;
        if (p2pEcdhHandshake(p2pAesKey)) {
            char* msg = create_encrypted_protocol_message("tactical_data.json", jsonString.toUtf8().constData(), (const uint8_t*)p2pAesKey.constData(), jwtToken.toUtf8().constData());
            if (msg) {
                p2pSocket->write(QByteArray(msg, strlen(msg)));
                p2pSocket->flush();
                free(msg);
                logInfo("P2P ile veri gönderildi");
                emit dataSendResult(SendSuccess, "P2P ile veri gönderildi");
                return true;
            }
        }
    }
    logError("Tüm gönderim denemeleri başarısız oldu");
    saveJsonToPending(jsonString); // Fallback başarısızsa pending'e kaydet
    emit dataSendResult(SendError, "Tüm gönderim denemeleri başarısız, veri kaydedildi");
    return false;
}

bool ClientWrapper::connectP2p(const QString& host, int port) {
    if (!p2pSocket) p2pSocket = new QTcpSocket(this);
    p2pSocket->connectToHost(host, port);
    if (!p2pSocket->waitForConnected(3000)) {
        logError("P2P sunucuya bağlanılamadı!");
        return false;
    }
    // Burada P2P için ECDH handshake ve anahtar üretimi eklenebilir (C'deki gibi)
    return true;
}

bool ClientWrapper::p2pEcdhHandshake(QByteArray& outAesKey) {
    ecdh_context_t p2pEcdhCtx;
    memset(&p2pEcdhCtx, 0, sizeof(ecdh_context_t));
    if (ecdh_init_context(&p2pEcdhCtx) == 0) return false;
    if (ecdh_generate_keypair(&p2pEcdhCtx) == 0) return false;

    // 1. Sunucudan public key'i al
    if (!p2pSocket->waitForReadyRead(3000)) return false;
    QByteArray serverPubKey = p2pSocket->read(ECC_PUB_KEY_SIZE);
    if (serverPubKey.size() != ECC_PUB_KEY_SIZE) return false;

    // 2. Kendi public key'ini gönder
    qint64 sent = p2pSocket->write((const char*)p2pEcdhCtx.public_key, ECC_PUB_KEY_SIZE);
    if (sent != ECC_PUB_KEY_SIZE) return false;
    p2pSocket->flush();

    // 3. Shared secret ve AES anahtarı üret
    if (ecdh_compute_shared_secret(&p2pEcdhCtx, (const uint8_t*)serverPubKey.constData()) == 0) return false;
    if (ecdh_derive_aes_key(&p2pEcdhCtx) == 0) return false;
    outAesKey = QByteArray((const char*)p2pEcdhCtx.aes_key, 32);
    return true;
}

// --- JSON'u pending klasörüne kaydet ---
void ClientWrapper::saveJsonToPending(const QString& jsonString) {
    QDir pendingDir(QCoreApplication::applicationDirPath() + "/pending");
    if (!pendingDir.exists()) pendingDir.mkpath(".");
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss_zzz");
    QString fileName = QString("pending_%1.json").arg(timestamp);
    QFile f(pendingDir.filePath(fileName));
    if (f.open(QIODevice::WriteOnly)) {
        QTextStream(&f) << jsonString;
        f.close();
        PRINTF_LOG("Veri pending klasörüne kaydedildi: %s\n", qPrintable(fileName));
    } else {
        PRINTF_LOG("Veri pending klasörüne kaydedilemedi!\n");
    }
}

void ClientWrapper::getReports() {
    qDebug() << "[DEBUG] getReports çağrıldı, jwtToken:" << jwtToken << ", handshakeCompleted:" << handshakeCompleted;
    // --- ECDH ve AES anahtarlarını logla ---
    qDebug() << "[DEBUG] getReports ECDH public_key:" << QByteArray((const char*)ecdhContext.public_key, ECC_PUB_KEY_SIZE).toHex();
    qDebug() << "[DEBUG] getReports ECDH shared_secret:" << QByteArray((const char*)ecdhContext.shared_secret, 32).toHex();
    qDebug() << "[DEBUG] getReports AES anahtarı (aesKey):" << QByteArray((const char*)aesKey, 32).toHex();
    qDebug() << "[DEBUG] getReports jwtToken:" << jwtToken;
    if (!isConnected() || !handshakeCompleted) { logError("Bağlantı yok veya ECDH tamamlanmamış, rapor sorgulanamaz"); return; }
    // Şifreli report query mesajı hazırla
    QJsonObject queryObj;
    queryObj["command"] = "REPORT_QUERY";
    queryObj["jwt"] = jwtToken;
    QJsonDocument doc(queryObj);
    QByteArray plain = doc.toJson(QJsonDocument::Compact);
    char* encryptedMsg = create_encrypted_protocol_message("REPORT_QUERY", plain.constData(), aesKey, jwtToken.toUtf8().constData());
    qDebug() << "[DEBUG] create_encrypted_protocol_message (REPORT_QUERY) jwtToken:" << jwtToken;
    QByteArray msgData(encryptedMsg, strlen(encryptedMsg));

        // ECDH ve AES anahtarı tamamlandıktan sonra C tarafı bağlantı nesnesini oluştur
    if (clientConnection) {
            close_connection(clientConnection);
            clientConnection = nullptr;
        }
        // Bağlantı zaten kurulu, sadece yapı oluşturulacak
        clientConnection = (client_connection_t*)calloc(1, sizeof(client_connection_t));
        if (clientConnection) {
        clientConnection->socket = tcpSocket->socketDescriptor();
        clientConnection->ecdh_ctx = ecdhContext;
        clientConnection->ecdh_initialized = true;
        clientConnection->type = CONN_TYPE_TCP;
        clientConnection->port = serverPort;

        // server_addr doldur
        memset(&clientConnection->server_addr, 0, sizeof(clientConnection->server_addr));
        clientConnection->server_addr.sin_family = AF_INET;
        clientConnection->server_addr.sin_port = htons(serverPort);
        QHostAddress host = tcpSocket->peerAddress();
        QByteArray addr = host.toString().toUtf8();
        inet_pton(AF_INET, addr.constData(), &clientConnection->server_addr.sin_addr);

        logInfo("[CHAT] clientConnection nesnesi ECDH sonrası oluşturuldu ve yapılandırıldı.");
    }

    printf("[DEBUG] ECDH handshake başlatıldı, public_key: %s\n", 
          QByteArray((const char*)ecdhContext.public_key, ECC_PUB_KEY_SIZE).toHex().constData());
    qDebug() << "[DEBUG] ECDH handshake başlatıldı, public_key:" 
             << QByteArray((const char*)ecdhContext.public_key, ECC_PUB_KEY_SIZE).toHex();
    printf("[DEBUG] Client Connection ECDH sonrası oluşturuldu, ecdh_ctx: %s\n", 
           clientConnection->ecdh_ctx);

    free(encryptedMsg);
    tcpSocket->write(msgData);
    tcpSocket->flush();
    tcpSocket->waitForBytesWritten();
}

// Basit bir şablon: Gerçek AES çözümleme fonksiyonu buraya eklemelisin
QByteArray ClientWrapper::decryptAes256Cbc(const QByteArray &cipher, const QByteArray &key, const QByteArray &iv) {
    // crypto_utils.h'daki decrypt_data fonksiyonunu kullan
    char* plain = decrypt_data(reinterpret_cast<const uint8_t*>(cipher.constData()), cipher.size(),
                              reinterpret_cast<const uint8_t*>(key.constData()), reinterpret_cast<const uint8_t*>(iv.constData()));
    if (!plain) {
        qWarning("decryptAes256Cbc: decrypt_data başarısız!");
        return QByteArray();
    }
    QByteArray result = QByteArray(plain, strlen(plain));
    free(plain);
    return result;
}

/**
 * @brief Admin rapora cevap gönderir
 * @param reportId Rapor ID'si
 * @param message Cevap mesajı
 */
void ClientWrapper::adminReplyToReport(int reportId, const QString& message) {
    // Mesaj boş olamaz kontrolü
    if (message.trimmed().isEmpty()) {
        emit dataError("Admin reply mesajı boş olamaz!");
        return;
    }
    
    // 5 kez deneme ile gönder
    bool success = false;
    for (int attempt = 1; attempt <= 5; attempt++) {
        emit dataInfo(QString("[DENEME %1/5] Admin reply gönderiliyor... Rapor ID: %2").arg(attempt).arg(reportId));
        
        if (trySendAdminReplyInternal(reportId, message.trimmed())) {
            emit dataSuccess(QString("Admin reply başarıyla gönderildi! Rapor ID: %1").arg(reportId));
            success = true;
            break;
        } else {
            emit dataError(QString("Admin reply gönderim hatası (Deneme %1/5)").arg(attempt));
            
            if (attempt < 5) {
                // Kısa bir bekleme
                QThread::msleep(500);
            }
        }
    }
    
    // 5 deneme de başarısızsa dosyaya kaydet
    if (!success) {
        saveAdminReplyToPending(reportId, message.trimmed());
        emit dataError(QString("Admin reply 5 denemede gönderilemedi, dosyaya kaydedildi. Rapor ID: %1").arg(reportId));
        
        // Eski dosyaları öncelikli göndermeyi dene
        sendAllPendingAdminReplies();
    }
}

/**
 * @brief Kendi reply'larını JWT ile sorgular
 */
void ClientWrapper::queryMyReplies() {
    if (!isConnected() || !handshakeCompleted) {
        logError("Bağlantı yok veya ECDH tamamlanmamış, reply sorgulanamaz");
        return;
    }
    
    // JSON formatında query mesajı oluştur
    QJsonObject queryObj;
    queryObj["jwt"] = jwtToken;
    
    QJsonDocument doc(queryObj);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    
    // Şifreli protokol mesajı oluştur
    char* encryptedMsg = create_encrypted_protocol_message("QUERY_MY_REPLIES", 
                                                          jsonData.constData(), 
                                                          aesKey, 
                                                          jwtToken.toUtf8().constData());
    if (!encryptedMsg) {
        logError("Reply query şifreli mesajı oluşturulamadı");
        return;
    }
    
    // Mesajı gönder
    QByteArray msgData(encryptedMsg, strlen(encryptedMsg));
    free(encryptedMsg);
    
    tcpSocket->write(msgData);
    tcpSocket->flush();
    
    logInfo("Kendi reply'lar sorgulandı");
}

/**
 * @brief Rapor cevaplarını izlemeyi başlatır
 * @details Sunucuya REPORT_REPLY_WATCH komutu gönderir ve gelen cevapları dinler
 *          Hem normal kullanıcı hem de admin için çalışır
 */
void ClientWrapper::watchReportReplies() {
    if (!isConnected()) {
        logError("Bağlantı yok, rapor cevapları izlenemez");
        return;
    }
    
    // Rapor cevabı izleme mesajı gönder
    QString watchCmd = QString("REPORT_REPLY_WATCH:%1").arg(jwtToken);
    QByteArray cmdData = watchCmd.toUtf8();
    
    tcpSocket->write(cmdData);
    tcpSocket->flush();
    
    logInfo("Rapor cevabı izleme başlatıldı");
}

/**
 * @brief Bağlantı türünü değiştirir
 * @param type Yeni bağlantı türü
 */
void ClientWrapper::switchConnectionType(ConnectionType type) {
    if (currentType == type) {
        logInfo("Aynı bağlantı türü zaten aktif");
        return;
    }
    
    // Mevcut bağlantıyı kapat
    if (isConnected()) {
        disconnectFromServer();
    }
    
    currentType = type;
    logInfo(QString("Bağlantı türü değiştirildi: %1").arg(getConnectionTypeString()));
}

/**
 * @brief Mevcut bağlantı türünün string karşılığını döner
 * @return QString Bağlantı türü string'i
 */
QString ClientWrapper::getConnectionTypeString() const {
    switch (currentType) {
        case ConnectionType::TCP: return "TCP";
        case ConnectionType::UDP: return "UDP";
        case ConnectionType::P2P: return "P2P";
        default: return "Unknown";
    }
}

/**
 * @brief UDP bağlantısını test eder
 * @return bool Test sonucu
 */
bool ClientWrapper::testUdpConnection() {
    if (!udpSocket) {
        udpSocket = new QUdpSocket(this);
    }
    
    // UDP test mesajı gönder (PING mesajı - sunucu bunu tanıyor)
    QByteArray testMsg = "PING";
    qint64 sent = udpSocket->writeDatagram(testMsg, QHostAddress(serverHost), serverPort + 1);
    
    if (sent <= 0) {
        logError("UDP test mesajı gönderilemedi");
        return false;
    }
    
    // Sunucudan yanıt bekle (3 saniye timeout)
    if (udpSocket->waitForReadyRead(3000)) {
        QByteArray responseData;
        QHostAddress senderHost;
        quint16 senderPort;
        
        while (udpSocket->hasPendingDatagrams()) {
            responseData.resize(udpSocket->pendingDatagramSize());
            udpSocket->readDatagram(responseData.data(), responseData.size(), &senderHost, &senderPort);
        }
        
        QString response = QString::fromUtf8(responseData);
        if (response.contains("UDP_SUCCESS")) {
            logInfo("UDP test bağlantısı başarılı - Yanıt alındı: " + response);
            return true;
        } else {
            logError("UDP test yanıtı beklenmedik: " + response);
            return false;
        }
    } else {
        logError("UDP test yanıtı alınamadı (timeout)");
        return false;
    }
}

/**
 * @brief P2P bağlantısını test eder
 * @return bool Test sonucu
 */
bool ClientWrapper::testP2pConnection() {
    if (!p2pSocket) {
        p2pSocket = new QTcpSocket(this);
    }
    
    // P2P port'una bağlanmayı dene
    p2pSocket->connectToHost(serverHost, serverPort + 2);
    
    if (p2pSocket->waitForConnected(3000)) {
        logInfo("P2P test bağlantısı başarılı");
        p2pSocket->disconnectFromHost();
        return true;
    } else {
        logError("P2P test bağlantısı başarısız");
        return false;
    }
}

/**
 * @brief Fallback mekanizması ile tüm protokolleri test eder
 * @param jsonString Test edilecek JSON verisi
 * @param encrypted Şifreli gönderim
 * @return bool Test sonucu
 */
bool ClientWrapper::testAllConnectionTypes(const QString& jsonString, bool encrypted) {
    emit fallbackTestResult("INFO", true, "Tüm bağlantı türleri test ediliyor...");
    
    // TCP test - gerçek bağlantı durumunu kontrol et
    emit fallbackTestResult("TCP", false, "TCP bağlantısı test ediliyor...");
    
    // Önce mevcut TCP bağlantısının gerçekten çalışıp çalışmadığını kontrol et
    bool tcpActuallyConnected = (tcpSocket && 
                                tcpSocket->state() == QAbstractSocket::ConnectedState && 
                                isConnected() && 
                                handshakeCompleted);
    
    if (tcpActuallyConnected) {
        // TCP gerçekten bağlı, test mesajı göndermeyi dene
        if (trySendJsonInternal(jsonString, encrypted)) {
            emit fallbackTestResult("TCP", true, "TCP bağlantısı aktif ve çalışıyor");
        } else {
            emit fallbackTestResult("TCP", false, "TCP bağlantısı var ama veri gönderilemedi");
            // Bağlantı durumunu güncelle
            connectionStatus = Disconnected;
            emit connectionStatusChanged(Disconnected, "TCP bağlantısı kesildiği tespit edildi");
        }
    } else {
        // TCP bağlantısı yok veya kopmuş, yeniden bağlanmayı dene
        if (tcpSocket) {
            tcpSocket->disconnectFromHost();
        }
        
        if (connectToServerInternal(serverHost, serverPort, ConnectionType::TCP)) {
            // Bağlantı kuruldu, ECDH handshake bekle
            QEventLoop loop;
            QTimer timer;
            timer.setSingleShot(true);
            timer.setInterval(5000); // 5 saniye timeout
            
            connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
            connect(this, &ClientWrapper::ecdhHandshakeCompleted, &loop, &QEventLoop::quit);
            
            timer.start();
            loop.exec();
            
            if (handshakeCompleted && trySendJsonInternal(jsonString, encrypted)) {
                emit fallbackTestResult("TCP", true, "TCP bağlantı testi başarılı");
            } else {
                emit fallbackTestResult("TCP", false, "TCP bağlantısı kuruldu ama ECDH veya veri gönderimi başarısız");
                disconnectFromServer();
            }
        } else {
            emit fallbackTestResult("TCP", false, "TCP bağlantısı kurulamadı");
        }
    }
    
    // UDP test
    emit fallbackTestResult("UDP", false, "UDP bağlantısı test ediliyor...");
    if (testUdpConnection()) {
        if (connectUdp(serverHost, serverPort + 1)) {
            QByteArray udpAesKey;
            if (udpEcdhHandshake(udpAesKey)) {
                emit fallbackTestResult("UDP", true, "UDP ECDH testi başarılı");
            } else {
                emit fallbackTestResult("UDP", false, "UDP ECDH başarısız");
            }
        } else {
            emit fallbackTestResult("UDP", false, "UDP bağlantısı kurulamadı");
        }
    } else {
        emit fallbackTestResult("UDP", false, "UDP test bağlantısı başarısız");
    }
    
    // P2P test
    emit fallbackTestResult("P2P", false, "P2P bağlantısı test ediliyor...");
    if (testP2pConnection()) {
        if (connectP2p(serverHost, serverPort + 2)) {
            QByteArray p2pAesKey;
            if (p2pEcdhHandshake(p2pAesKey)) {
                emit fallbackTestResult("P2P", true, "P2P ECDH testi başarılı");
            } else {
                emit fallbackTestResult("P2P", false, "P2P ECDH başarısız");
            }
        } else {
            emit fallbackTestResult("P2P", false, "P2P bağlantısı kurulamadı");
        }
    } else {
        emit fallbackTestResult("P2P", false, "P2P test bağlantısı başarısız");
    }
    
    emit fallbackTestResult("INFO", true, "Tüm bağlantı testleri tamamlandı");
    return true;
}

/**
 * @brief İç bağlantı kurma fonksiyonu - fallback test için
 * @param host Sunucu host'u
 * @param port Sunucu port'u
 * @param type Bağlantı türü
 * @return bool Bağlantı sonucu
 */
bool ClientWrapper::connectToServerInternal(const QString& host, int port, ConnectionType type) {
    switch (type) {
        case ConnectionType::TCP:
            if (!tcpSocket) tcpSocket = new QTcpSocket(this);
            tcpSocket->connectToHost(host, port);
            return tcpSocket->waitForConnected(3000);
            
        case ConnectionType::UDP:
            return connectUdp(host, port);
            
        case ConnectionType::P2P:
            return connectP2p(host, port);
            
        default:
            return false;
    }
}

/**
 * @brief Gelişmiş hata yönetimi ve fallback durumu raporu
 * @param error Hata mesajı
 * @param canFallback Fallback mümkün mü
 */
void ClientWrapper::handleAdvancedError(const QString& error, bool canFallback) {
    logError(error);
    
    if (canFallback) {
        logInfo("Fallback mekanizması deneniyor...");
        emit connectionStatusChanged(Connecting, "Alternatif bağlantı deneniyor...");
        
        // Otomatik fallback tetikle
        QTimer::singleShot(1000, this, [this]() {
            // Test verisi ile fallback dene
            QString testJson = createTacticalDataJson(0.0, 0.0, "fallback_test", "Fallback test");
            trySendWithFallback(testJson, true);
        });
    }
}

/**
 * @brief Admin bildirim dinleme komutu gönder
 */
void ClientWrapper::listenForAdminNotifications()
{
    if (!isConnected()) {
        logError("Bağlantı yok, admin bildirimleri dinlenemez");
        return;
    }
    if (jwtToken.isEmpty()) {
        logError("JWT token yok, admin bildirimleri dinlenemez");
        return;
    }
    QString cmd = QString("ADMIN_NOTIFY_LISTEN:%1").arg(jwtToken);
    QByteArray cmdData = cmd.toUtf8();
    tcpSocket->write(cmdData);
    tcpSocket->flush();
    logInfo("Admin bildirim dinleme başlatıldı");
}

// --- Parçalı ENCRYPTED_PART yanıtlarını işler ---
void ClientWrapper::processEncryptedParts()
{
    // ENCRYPTED_PART: formatını ara ve işle
    while (true) {
        int headerIdx = incomingBuffer.indexOf("ENCRYPTED_PART:");
        if (headerIdx == -1) break;
        
        // Header'dan sonraki kısmı al
        int afterHeader = headerIdx + 15; // "ENCRYPTED_PART:" uzunluğu
        if (afterHeader >= incomingBuffer.size()) break; // Yetersiz veri
        
        // Header parse et: idx:total:length:
        QByteArray headerData = incomingBuffer.mid(afterHeader, 50); // Yeterli uzunluk al
        QList<QByteArray> parts = headerData.split(':');
        if (parts.size() < 4) {
            // Header tam gelmemiş, veri bekle
            break;
        }
        
        int idx = parts[0].toInt();
        int total = parts[1].toInt();
        int plen = parts[2].toInt();
        
        // Header'ın sonunu bul (3. ':' karakterine kadar)
        int colonCount = 0;
        int hexStart = afterHeader;
        while (hexStart < incomingBuffer.size() && colonCount < 3) {
            if (incomingBuffer[hexStart] == ':') colonCount++;
            hexStart++;
        }
        
        if (colonCount < 3) break; // Header tam gelmemiş
        
        // Yeterli hex verisi var mı kontrol et
        if (hexStart + plen > incomingBuffer.size()) {
            qDebug() << "[DEBUG] Yeterli hex verisi yok: needed=" << plen << ", available=" << (incomingBuffer.size() - hexStart);
            break; // Daha fazla veri bekle
        }
        
        // Hex veriyi al
        QByteArray hexData = incomingBuffer.mid(hexStart, plen);
        
        qDebug() << "[DEBUG] ENCRYPTED_PART" << idx << "/" << total << "plen=" << plen << "alındı";
        qDebug() << "[DEBUG] Hex data (ilk 32):" << hexData.left(32);
        
        // İlk parça mı?
        if (!isProcessingParts) {
            resetPartProcessing();
            isProcessingParts = true;
            expectedParts = total;
        }
        
        // Hex veriyi biriktir
        allHexData.append(hexData);
        receivedParts++;
        
        // Bu parçayı buffer'dan çıkar
        int consumed = hexStart + plen - headerIdx;
        incomingBuffer.remove(headerIdx, consumed);
        
        qDebug() << "[DEBUG] Parça" << receivedParts << "/" << expectedParts << "işlendi";
        
        // Tüm parçalar alındı mı?
        if (receivedParts >= expectedParts) {
            finalizePartProcessing();
            break;
        }
    }
}

/**
 * @brief Tek parçalı ENCRYPTED yanıtlarını işler
 */
void ClientWrapper::processEncryptedResponse()
{
    // Tek parçalı ENCRYPTED: yanıtı ara
    int encIdx = incomingBuffer.indexOf("ENCRYPTED:");
    if (encIdx != -1 && incomingBuffer.indexOf("ENCRYPTED_PART:") == -1) {
        // Tek parça yanıt bulundu
        int dataStart = encIdx + 10; // "ENCRYPTED:" uzunluğu
        int lineEnd = incomingBuffer.indexOf('\n', dataStart);
        if (lineEnd == -1 && incomingBuffer.size() - dataStart > 100) {
            // Satır sonu yok ama yeterli veri var, tümünü al
            lineEnd = incomingBuffer.size();
        }
        if (lineEnd != -1) {
            QByteArray fullData = incomingBuffer.mid(dataStart, lineEnd - dataStart);
            qDebug() << "[DEBUG] Tek parça ENCRYPTED yanıt bulundu, uzunluk:" << fullData.size();
            qDebug() << "[DEBUG] Full data (ilk 100):" << QString(fullData.left(100));
            // Format kontrolü: filename:hex_data:jwt_token veya sadece hex_data
            QList<QByteArray> dataParts = fullData.split(':');
            QByteArray hexData;
            if (dataParts.size() >= 3) {
                // Format: filename:hex_data:jwt_token
                hexData = dataParts[1];
                qDebug() << "[DEBUG] Format: filename:hex_data:jwt_token, hex uzunluk:" << hexData.size();
                qDebug() << "[DEBUG] Hex data parçası:" << QString(hexData.left(64));
            } else if (dataParts.size() == 2) {
                // Format: filename:hex_data (JWT yok)
                hexData = dataParts[1];
                qDebug() << "[DEBUG] Format: filename:hex_data, hex uzunluk:" << hexData.size();
                qDebug() << "[DEBUG] Hex data parçası:" << QString(hexData.left(64));
            } else {
                // Direkt hex data
                hexData = fullData;
                qDebug() << "[DEBUG] Format: direkt hex data, uzunluk:" << hexData.size();
                qDebug() << "[DEBUG] Raw hex data (ilk 64):" << QString(hexData.left(64));
            }
            // Hex veriyi temizle (sadece hex karakterler) - trim de yap
            hexData = hexData.trimmed();
            QByteArray cleanHex;
            for (char c : hexData) {
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                    cleanHex.append(c);
                }
            }
            qDebug() << "[DEBUG] Temizlenmiş hex uzunluk:" << cleanHex.size();
            qDebug() << "[DEBUG] Temizlenmiş hex (ilk 32):" << QString(cleanHex.left(32));
            // Hex'i binary'ye çevir ve decrypt et
            QByteArray binData = QByteArray::fromHex(cleanHex);
            if (binData.size() >= 16) {
                QByteArray iv = binData.left(16);
                QByteArray enc = binData.mid(16);
                qDebug() << "[DEBUG] IV:" << iv.toHex();
                qDebug() << "[DEBUG] Encrypted size:" << enc.size();
                QByteArray plainJson = decryptAes256Cbc(enc, QByteArray(reinterpret_cast<const char*>(aesKey), 32), iv);
                if (!plainJson.isEmpty()) {
                    qDebug() << "[DEBUG] Decrypt başarılı, JSON size:" << plainJson.size();
                    qDebug() << "[DEBUG] Full JSON:" << QString(plainJson);
                    QJsonDocument doc = QJsonDocument::fromJson(plainJson);
                    if (doc.isObject()) {
                        QJsonObject obj = doc.object();
                        // REPORT_LIST yanıtı
                        if (obj.contains("reports") && obj["reports"].isArray()) {
                            int privilege = obj.contains("privilege") ? obj["privilege"].toInt() : 0;
                            emit reportsReceived(obj["reports"].toArray(), privilege);
                        }
                        // QUERY_MY_REPLIES yanıtı
                        else if (obj.contains("replies") && obj["replies"].isArray()) {
                            qDebug() << "[DEBUG] QUERY_MY_REPLIES yanıtı bulundu, replies array size:" << obj["replies"].toArray().size();
                            // Log decrypted QUERY_MY_REPLIES JSON
                            QJsonDocument logDoc(obj["replies"].toArray());
                            emit logMessage(QString("<b>[QUERY_MY_REPLIES][DECRYPT]</b> %1 adet reply çözüldü:<br><pre>%2</pre>")
                                .arg(obj["replies"].toArray().size())
                                .arg(QString::fromUtf8(logDoc.toJson(QJsonDocument::Indented))));
                            emit replyQueryResultReceived(obj["replies"].toArray());
                        }
                        // Chat room list yanıtı ("rooms" array)
                        else if (obj.contains("rooms") && obj["rooms"].isArray()) {
                            qDebug() << "[DEBUG] Chat room list yanıtı bulundu, rooms array size:" << obj["rooms"].toArray().size();
                            emit chatRoomListReceived(obj["rooms"].toArray());
                        }
                        // Tüm kullanıcıların son konumları yanıtı (admin) veya birim son konumları (normal kullanıcı)
                        else if (obj.contains("locations") && obj["locations"].isArray()) {
                            if (obj.contains("type") && obj["type"].toString() == "my_unit") {
                                emit myUnitLatestLocationsReceived(obj["locations"].toArray());
                            } else {
                                emit allUsersLatestLocationsReceived(obj["locations"].toArray());
                            }
                        }
                        // Diğer yanıtlar
                        else {
                            emit dataReceived(QString::fromUtf8(plainJson));
                        }
                    }
                } else {
                    qDebug() << "[DEBUG] Decrypt başarısız";
                }
            }
            // Bu mesajı buffer'dan çıkar
            incomingBuffer.remove(encIdx, lineEnd - encIdx + (lineEnd < incomingBuffer.size() ? 1 : 0));
        }
    }
}

/**
 * @brief Parça işleme durumunu sıfırlar
 */
void ClientWrapper::resetPartProcessing()
{
    allHexData.clear();
    allPlainData.clear();
    expectedParts = 0;
    receivedParts = 0;
    isProcessingParts = false;
}

/**
 * @brief Parçalı işleme tamamlandığında çağrılır
 */
void ClientWrapper::finalizePartProcessing()
{
    qDebug() << "[DEBUG] Tüm parçalar alındı, toplam hex uzunluk:" << allHexData.size();
    qDebug() << "[DEBUG] İlk 64 hex:" << allHexData.left(64);
    
    // Hex'i binary'ye çevir
    QByteArray binData = QByteArray::fromHex(allHexData);
    if (binData.size() >= 16) {
        QByteArray iv = binData.left(16);
        QByteArray enc = binData.mid(16);
        
        qDebug() << "[DEBUG] IV:" << iv.toHex();
        qDebug() << "[DEBUG] Encrypted size:" << enc.size();
        
        // Decrypt et
        QByteArray plainJson = decryptAes256Cbc(enc, QByteArray(reinterpret_cast<const char*>(aesKey), 32), iv);
        
        if (!plainJson.isEmpty()) {
            qDebug() << "[DEBUG] Parçalı decrypt başarılı, JSON size:" << plainJson.size();
            // qDebug() << "[DEBUG] Full JSON:" << QString(plainJson);
            
            // JSON parse et ve raporları emit et
            QJsonDocument doc = QJsonDocument::fromJson(plainJson);
            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                
                // REPORT_LIST yanıtı
                if (obj.contains("reports") && obj["reports"].isArray()) {
                    int privilege = obj.contains("privilege") ? obj["privilege"].toInt() : 0;
                    emit reportsReceived(obj["reports"].toArray(), privilege);
                    qDebug() << "[DEBUG] Raporlar emit edildi, sayı:" << obj["reports"].toArray().size();
                }
                // QUERY_MY_REPLIES yanıtı  
                else if (obj.contains("replies") && obj["replies"].isArray()) {
                    qDebug() << "[DEBUG] QUERY_MY_REPLIES yanıtı bulundu (parçalı), replies array size:" << obj["replies"].toArray().size();
                    emit replyQueryResultReceived(obj["replies"].toArray());
                }
                else {
                    qDebug() << "[DEBUG] JSON'da bilinen format bulunamadı";
                    emit dataReceived(QString::fromUtf8(plainJson));
                }
            } else {
                qDebug() << "[DEBUG] JSON parse edilemedi";
            }
        } else {
            qDebug() << "[DEBUG] Parçalı decrypt başarısız";
        }
    } else {
        qDebug() << "[DEBUG] Binary data çok kısa:" << binData.size();
    }
    
    // Temizle
    resetPartProcessing();
}

// === RETRY MEKANİZMASI FONKSİYONLARI ===

/**
 * @brief Retry mekanizması ile fallback dener
 */
void ClientWrapper::retryWithFallback(const QString& jsonData, bool encrypted) {
    PRINTF_LOG("[RETRY] Başlıyor - currentType: %d\n", (int)currentType);
    
    // Mevcut bağlantı türü için retry sayacını kontrol et
    int* currentRetryCount = nullptr;
    QString connectionTypeName;
    
    switch(currentType) {
        case ConnectionType::TCP:
            currentRetryCount = &tcpRetryCount;
            connectionTypeName = "TCP";
            break;
        case ConnectionType::UDP:
            currentRetryCount = &udpRetryCount;
            connectionTypeName = "UDP";
            break;
        case ConnectionType::P2P:
            currentRetryCount = &p2pRetryCount;
            connectionTypeName = "P2P";
            break;
    }
    
    if (currentRetryCount && *currentRetryCount < MAX_RETRY_COUNT) {
        (*currentRetryCount)++;
        PRINTF_LOG("[RETRY] %s retry %d/%d deneniyor...\n", 
                   connectionTypeName.toUtf8().constData(), *currentRetryCount, MAX_RETRY_COUNT);
        
        emit fallbackTestResult(connectionTypeName, false, 
                               QString("Retry %1/%2 deneniyor...").arg(*currentRetryCount).arg(MAX_RETRY_COUNT));
        
        // Mevcut bağlantı türü ile tekrar dene
        if (currentType == ConnectionType::TCP) {
            connectToServerInternal(serverHost, serverPort, ConnectionType::TCP);
            if (isConnected() && trySendJsonInternal(jsonData, encrypted)) {
                resetRetryCounters();
                emit dataSendResult(SendSuccess, "Retry ile başarılı gönderim");
                return;
            }
        }
        
        // Mevcut türde hala başarısız, sonraki retry'ı dene
        QTimer::singleShot(1000, [this, jsonData, encrypted]() {
            retryWithFallback(jsonData, encrypted);
        });
        
    } else {
        // Maksimum retry sayısına ulaşıldı, sonraki bağlantı türüne geç
        PRINTF_LOG("[RETRY] %s maksimum retry'a ulaştı, sonraki türe geçiliyor...\n", 
                   connectionTypeName.toUtf8().constData());
        
        if (!tryNextConnectionType(jsonData, encrypted)) {
            // Tüm bağlantı türleri denendi ve başarısız oldu
            PRINTF_LOG("[RETRY] Tüm bağlantı türleri başarısız, veri pending'e kaydediliyor\n");
            saveJsonToPending(jsonData);
            resetRetryCounters();
            emit dataSendResult(SendError, "Tüm bağlantı türleri başarısız, veri kaydedildi");
            emit fallbackTestResult("ALL", false, "Tüm bağlantı türleri başarısız");
        }
    }
}

/**
 * @brief Sonraki bağlantı türüne geçer
 */
bool ClientWrapper::tryNextConnectionType(const QString& jsonData, bool encrypted) {
    ConnectionType nextType;
    
    switch(currentType) {
        case ConnectionType::TCP:
            nextType = ConnectionType::UDP;
            break;
        case ConnectionType::UDP:
            nextType = ConnectionType::P2P;
            break;
        case ConnectionType::P2P:
            // Tüm türler denendi
            return false;
    }
    
    QString nextTypeName;
    switch(nextType) {
        case ConnectionType::UDP: nextTypeName = "UDP"; break;
        case ConnectionType::P2P: nextTypeName = "P2P"; break;
        default: nextTypeName = "TCP"; break;
    }
    
    PRINTF_LOG("[RETRY] %s türüne geçiliyor...\n", nextTypeName.toUtf8().constData());
    emit fallbackTestResult(nextTypeName, false, "Bağlantı türü değiştiriliyor...");
    
    // Mevcut bağlantıyı kapat
    disconnectFromServer();
    
    // Yeni bağlantı türüne geç
    currentType = nextType;
    emit connectionTypeChanged(currentType);
    
    // Yeni türle bağlantı kurmayı dene
    if (nextType == ConnectionType::UDP) {
        if (connectUdp(serverHost, serverPort + 1)) {
            QByteArray udpAesKey;
            if (udpEcdhHandshake(udpAesKey)) {
                // UDP ECDH başarılı, veri göndermeyi dene
                // UDP için özel gönderim fonksiyonu gerekebilir
                emit fallbackTestResult("UDP", true, "UDP bağlantısı başarılı");
                resetRetryCounters();
                return true;
            }
        }
    } else if (nextType == ConnectionType::P2P) {
        if (connectP2p(serverHost, serverPort + 2)) {
            QByteArray p2pAesKey;
            if (p2pEcdhHandshake(p2pAesKey)) {
                // P2P ECDH başarılı, veri göndermeyi dene
                emit fallbackTestResult("P2P", true, "P2P bağlantısı başarılı");
                resetRetryCounters();
                return true;
            }
        }
    }
    
    // Yeni türle bağlantı kurulamadı, retry mekanizmasını başlat
    retryWithFallback(jsonData, encrypted);
    return true;
}

/**
 * @brief Retry sayaçlarını sıfırlar
 */
void ClientWrapper::resetRetryCounters() {
    tcpRetryCount = 0;
    udpRetryCount = 0;
    p2pRetryCount = 0;
    PRINTF_LOG("[RETRY] Sayaçlar sıfırlandı\n");
}

/**
 * @brief Bağlantı hatası durumunu yönetir
 */
void ClientWrapper::handleConnectionFailure(ConnectionType failedType, const QString& error) {
    QString typeName;
    switch(failedType) {
        case ConnectionType::TCP: typeName = "TCP"; break;
        case ConnectionType::UDP: typeName = "UDP"; break;
        case ConnectionType::P2P: typeName = "P2P"; break;
    }
    
    PRINTF_LOG("[RETRY] %s bağlantı hatası: %s\n", 
               typeName.toUtf8().constData(), error.toUtf8().constData());
    
    emit fallbackTestResult(typeName, false, error);
    
    // Eğer bekleyen veri varsa retry mekanizmasını başlat
    if (!lastJsonData.isEmpty()) {
        retryWithFallback(lastJsonData, lastEncryptionFlag);
    }
}

/**
 * @brief Admin reply'ı internal olarak gönderir
 */
bool ClientWrapper::trySendAdminReplyInternal(int reportId, const QString& message) {
    if (!isConnected() || !handshakeCompleted) {
        // Bağlantı yoksa yeniden bağlanmayı dene
        connectToServer(serverHost, serverPort);
        
        // Bağlantı kontrolü yap
        if (!isConnected() || !handshakeCompleted) {
            return false;
        }
    }
    
    try {
        // JSON formatında admin reply mesajı oluştur
        QJsonObject replyObj;
        replyObj["report_id"] = reportId;
        replyObj["msg"] = message;
        
        QJsonDocument doc(replyObj);
        QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
        
        // Şifreli protokol mesajı oluştur
        char* encryptedMsg = create_encrypted_protocol_message("REPLY_REPORT", 
                                                              jsonData.constData(), 
                                                              aesKey, 
                                                              jwtToken.toUtf8().constData());
        if (!encryptedMsg) {
            return false;
        }
        
        // Mesajı gönder
        QByteArray msgData(encryptedMsg, strlen(encryptedMsg));
        free(encryptedMsg);
        
        if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
            qint64 written = tcpSocket->write(msgData);
            tcpSocket->flush();
            
            if (written > 0) {
                // Yanıt bekle
                if (tcpSocket->waitForReadyRead(3000)) {
                    QByteArray response = tcpSocket->readAll();
                    
                    // Başarılı yanıt kontrolü (basit)
                    if (response.contains("SUCCESS") || response.contains("OK")) {
                        return true;
                    }
                }
                return true; // Yanıt alamasak da gönderim başarılı sayılır
            }
        }
        
        return false;
    } catch (...) {
        return false;
    }
}

/**
 * @brief Admin reply'ı dosyaya kaydeder
 */
void ClientWrapper::saveAdminReplyToPending(int reportId, const QString& message) {
    try {
        QString pendingDir = "pending_admin_replies";
        QDir().mkpath(pendingDir);
        
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd_HH-mm-ss-zzz");
        QString filename = QString("%1/admin_reply_%2_%3.json").arg(pendingDir).arg(reportId).arg(timestamp);
        
        QJsonObject replyObj;
        replyObj["report_id"] = reportId;
        replyObj["msg"] = message;
        replyObj["timestamp"] = timestamp;
        replyObj["retry_count"] = 0;
        
        QJsonDocument doc(replyObj);
        
        QFile file(filename);
        if (file.open(QIODevice::WriteOnly)) {
            file.write(doc.toJson());
            file.close();
        }
    } catch (...) {
        // Sessizce geç
    }
}

/**
 * @brief Bekleyen admin reply'ları gönderir
 */
void ClientWrapper::sendAllPendingAdminReplies() {
    try {
        QDir pendingDir("pending_admin_replies");
        if (!pendingDir.exists()) return;
        
        QStringList jsonFiles = pendingDir.entryList(QStringList() << "*.json", QDir::Files, QDir::Time);
        
        for (const QString& filename : jsonFiles) {
            QString filePath = pendingDir.absoluteFilePath(filename);
            
            QFile file(filePath);
            if (file.open(QIODevice::ReadOnly)) {
                QByteArray data = file.readAll();
                file.close();
                
                QJsonDocument doc = QJsonDocument::fromJson(data);
                QJsonObject obj = doc.object();
                
                int reportId = obj["report_id"].toInt();
                QString message = obj["msg"].toString();
                
                if (trySendAdminReplyInternal(reportId, message)) {
                    // Başarılı gönderim, dosyayı sil
                    QFile::remove(filePath);
                    emit dataSuccess(QString("Bekleyen admin reply gönderildi: Rapor ID %1").arg(reportId));
                } else {
                    // Başarısız, dosyayı koru
                    break;
                }
            }
        }
    } catch (...) {
        // Sessizce geç
    }
}

/**
 * @brief Belirli bir rapor ID'si için admin reply'ları sorgular
 */
void ClientWrapper::queryRepliesForReport(int reportId) {
    if (!isConnected() || !handshakeCompleted) {
        emit dataError("Bağlantı yok veya ECDH tamamlanmamış, reply sorgulanamaz");
        return;
    }
    
    try {
        // JSON formatında sorgu mesajı oluştur (JWT ile - tüm reply'ları al)
        QJsonObject queryObj;
        queryObj["jwt"] = jwtToken;
        // report_id göndermiyoruz, tüm reply'ları alacağız
        
        QJsonDocument doc(queryObj);
        QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
        
        // Şifreli protokol mesajı oluştur
        char* encryptedMsg = create_encrypted_protocol_message("QUERY_MY_REPLIES", 
                                                              jsonData.constData(), 
                                                              aesKey, 
                                                              jwtToken.toUtf8().constData());
        if (!encryptedMsg) {
            emit dataError("Reply sorgu mesajı oluşturulamadı");
            return;
        }
        
        // Mesajı gönder
        QByteArray msgData(encryptedMsg, strlen(encryptedMsg));
        free(encryptedMsg);
        
        if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
            tcpSocket->write(msgData);
            tcpSocket->flush();
            
            emit dataInfo(QString("Admin cevapları sorgulanıyor..."));
        }
    } catch (...) {
        emit dataError("Reply sorgulama hatası");
    }
}

/**
 * @brief Konum bilgisini sunucuya gönderir (taktik veri gibi, JSON ile)
 * @param latitude Enlem
 * @param longitude Boylam
 * @param timestamp Unix zaman damgası
 * @param description Açıklama (opsiyonel)
 * @param encrypted Şifreli gönderim
 */
void ClientWrapper::sendLocation(double latitude, double longitude, long timestamp, const QString& description, bool encrypted)
{
    if (!isConnected()) {
        PRINTF_LOG("✗ Not connected to server - cannot send location\n");
        LOG_CLIENT_ERROR("Attempted to send location while not connected");
        emit dataSendResult(NotConnected, "Sunucuya bağlı değilsiniz");
        return;
    }
    if (jwtToken.isEmpty()) {
        PRINTF_LOG("✗ JWT token yok - konum gönderilemiyor\n");
        LOG_CLIENT_ERROR("JWT token yok - konum gönderilemedi");
        emit dataSendResult(InvalidData, "JWT token yok, konum gönderilemedi");
        return;
    }
    if (std::isnan(latitude) || std::isnan(longitude)) {
        PRINTF_LOG("✗ Geçersiz konum verisi (NaN)\n");
        LOG_CLIENT_ERROR("Geçersiz konum verisi (NaN)");
        emit dataSendResult(InvalidData, "Geçersiz konum verisi (NaN)");
        return;
    }
    QJsonObject jsonObj;
    jsonObj["latitude"] = latitude;
    jsonObj["longitude"] = longitude;
    jsonObj["timestamp"] = static_cast<qint64>(timestamp);
    jsonObj["jwt"] = jwtToken;
    if (!description.isEmpty())
        jsonObj["description"] = description;
    QJsonDocument jsonDoc(jsonObj);
    QString jsonString = jsonDoc.toJson(QJsonDocument::Compact);
    // Komut adını belirtmek için protokol mesajı oluşturulurken komut adı kullanılacak
    sendLocationJson(jsonString, encrypted);
}

/**
 * @brief Konum JSON'unu uygun protokol ile gönderir
 * @param jsonString JSON verisi
 * @param encrypted Şifreli gönderim
 */
void ClientWrapper::sendLocationJson(const QString& jsonString, bool encrypted)
{
    // Bağlantı ve handshake kontrolü
    if (!isConnected()) {
        PRINTF_LOG("[KONUM][SEND][ERROR] Not connected, konum JSON gönderilemiyor\n");
        logError("[KONUM][SEND][ERROR] Not connected, konum JSON gönderilemiyor");
        return;
    }
    if (encrypted && !handshakeCompleted) {
        PRINTF_LOG("[KONUM][SEND][ERROR] ECDH handshake tamamlanmamış, şifreli konum gönderilemez\n");
        logError("[KONUM][SEND][ERROR] ECDH handshake tamamlanmamış, şifreli konum gönderilemez");
        return;
    }
    char* protocolMessage = nullptr;
    if (encrypted) {
        protocolMessage = create_encrypted_protocol_message("INSERT_LOCATION", jsonString.toUtf8().constData(), aesKey, jwtToken.toUtf8().constData());
    } else {
        protocolMessage = create_normal_protocol_message("INSERT_LOCATION", jsonString.toUtf8().constData(), jwtToken.toUtf8().constData());
    }
    if (!protocolMessage) {
        PRINTF_LOG("[KONUM][SEND][ERROR] Protocol message oluşturulamadı\n");
        logError("[KONUM][SEND][ERROR] Protocol message oluşturulamadı");
        return;
    }
    QByteArray messageData(protocolMessage, strlen(protocolMessage));
    qint64 bytesWritten = tcpSocket->write(messageData);
    tcpSocket->flush();
    free(protocolMessage);
    if (bytesWritten == -1) {
        PRINTF_LOG("[KONUM][SEND][ERROR] Protocol message gönderilemedi, tcpSocket error: %s\n", tcpSocket->errorString().toUtf8().constData());
        logError(QString("[KONUM][SEND][ERROR] tcpSocket->write() error: %1").arg(tcpSocket->errorString()));
        return;
    } else {
        PRINTF_LOG("[KONUM][SEND] Konum başarıyla gönderildi (%lld bytes)\n", bytesWritten);
        logInfo(QString("[KONUM][SEND] Konum başarıyla gönderildi (%1 bytes)").arg(bytesWritten));
        // emit dataSendResult(SendSuccess, "Konum başarıyla gönderildi"); // Bildirim kutusu çıkmasın diye kapatıldı
    }
}

/**
 * @brief Tüm kullanıcıların son konumlarını sunucudan çeker (sadece admin için)
 */
void ClientWrapper::sendSelectLatestLocationsAllUsers()
{
    if (!isConnected() || !handshakeCompleted) {
        logError("Bağlantı yok veya ECDH tamamlanmamış, tüm kullanıcı konumları sorgulanamaz");
        return;
    }
    if (jwtToken.isEmpty()) {
        logError("JWT token yok, tüm kullanıcı konumları sorgulanamaz");
        return;
    }
    // Komut JSON'u hazırla
    QJsonObject queryObj;
    queryObj["jwt"] = jwtToken;
    QJsonDocument doc(queryObj);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    char* encryptedMsg = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_ALL_USERS",
                                                          jsonData.constData(),
                                                          aesKey,
                                                          jwtToken.toUtf8().constData());
    if (!encryptedMsg) {
        logError("Tüm kullanıcı konumları için şifreli mesaj oluşturulamadı");
        return;
    }
    QByteArray msgData(encryptedMsg, strlen(encryptedMsg));
    free(encryptedMsg);
    tcpSocket->write(msgData);
    tcpSocket->flush();
    logInfo("Tüm kullanıcıların son konumları sorgulandı");
}

/**
 * @brief Sadece normal kullanıcılar için birimin son konumlarını sunucudan çeker
 */
void ClientWrapper::sendSelectLatestLocationsByCurrentUnit()
{
    if (!isConnected() || !handshakeCompleted) {
        logError("Bağlantı yok veya ECDH tamamlanmamış, birim konumları sorgulanamaz");
        return;
    }
    if (jwtToken.isEmpty()) {
        logError("JWT token yok, birim konumları sorgulanamaz");
        return;
    }
    // Komut JSON'u hazırla
    QJsonObject queryObj;
    queryObj["jwt"] = jwtToken;
    QJsonDocument doc(queryObj);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    char* encryptedMsg = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_MY_UNIT",
                                                          jsonData.constData(),
                                                          aesKey,
                                                          jwtToken.toUtf8().constData());
    if (!encryptedMsg) {
        logError("Birim konumları için şifreli mesaj oluşturulamadı");
        return;
    }
    QByteArray msgData(encryptedMsg, strlen(encryptedMsg));
    free(encryptedMsg);
    tcpSocket->write(msgData);
    tcpSocket->flush();
    logInfo("Birim son konumları sorgulandı");
}

void ClientWrapper::requestChatRoomList()
{
    if (!isConnected() || !handshakeCompleted) {
        logError("[CHAT] Bağlantı yok veya ECDH tamamlanmamış, chat odaları sorgulanamaz");
        emit chatRoomListReceived(QJsonArray());
        return;
    }
    if (jwtToken.isEmpty()) {
        logError("[CHAT] JWT token yok, chat odaları sorgulanamaz");
        emit chatRoomListReceived(QJsonArray());
        return;
    }

    // Sadece istek gönder, yanıt processEncryptedResponse ile asenkron işlenecek
    if (!clientConnection) {
        logError("[CHAT] clientConnection yok, chat odaları sorgulanamaz");
        emit chatRoomListReceived(QJsonArray());
        return;
    }
    int res = send_list_rooms_request(clientConnection, jwtToken.toUtf8().constData());
    if (res != 0) {
        logError("[CHAT] send_list_rooms_request başarısız oldu");
        emit chatRoomListReceived(QJsonArray());
        return;
    }
    qDebug() << "[DEBUG] Chat room list request sent (send_list_rooms_request)";
    // Yanıt processEncryptedResponse ile asenkron işlenecek

}