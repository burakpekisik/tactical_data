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

/**
 * @brief ClientWrapper constructor'ı
 * @param parent        // Shared secret hesapla
        if (ecdh_compute_shared_secret(&ecdhContext, 
                                      reinterpret_cast<const uint8_t*>(serverPublicKey.constData())) == 0) {
            LOG_CLIENT_ERROR("Failed to compute shared secret");
            logError("Shared secret hesaplanamadı");
            return;
        }
        
        // AES anahtarını türet
        if (ecdh_derive_aes_key(&ecdhContext) == 0) {
            LOG_CLIENT_ERROR("Failed to derive AES key");
            logError("AES anahtar türetme hatası");
            return;
        }*/
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
    return connectionStatus == Connected;
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
    
    // ECDH anahtar değişimini başlat
    initializeECDHHandshake();
    
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
    
    PRINTF_LOG("Raw data received (%d bytes)\n", data.size());
    LOG_CLIENT_DEBUG("Received raw data from server: %d bytes", data.size());
    
    // ECDH handshake response'unu kontrol et (server public key)
    if (!handshakeCompleted && data.size() == ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Received server public key (%d bytes)\n", data.size());
        LOG_CLIENT_INFO("Processing server public key for ECDH handshake");
        processECDHResponse(data);
        return;
    }
    
    QString dataString = QString::fromUtf8(data);
    
    // Veri şifreli mi kontrol et
    if (dataString.startsWith("ENCRYPTED:")) {
        PRINTF_LOG("Encrypted data detected, attempting to decrypt...\n");
        LOG_CLIENT_INFO("Received encrypted data from server");
        
        // ENCRYPTED: prefix'ini kaldır
        QByteArray encryptedData = data.mid(10); // "ENCRYPTED:" = 10 karakter
        
        // Base64 decode
        QByteArray decodedData = QByteArray::fromBase64(encryptedData);
        
        // ECDH handshake tamamlandıysa gerçek anahtar kullan
        uint8_t* keyToUse = handshakeCompleted ? aesKey : nullptr;
        uint8_t tempKey[32];
        uint8_t tempIv[16];
        
        if (!handshakeCompleted) {
            // Geçici anahtar kullan (demo amaçlı)
            for (int i = 0; i < 32; i++) tempKey[i] = 0x2b + i;
            keyToUse = tempKey;
        }
        for (int i = 0; i < 16; i++) tempIv[i] = 0x3c + i;
        
        char* decryptedData = decrypt_data(reinterpret_cast<const uint8_t*>(decodedData.constData()), 
                                         decodedData.size(), keyToUse, tempIv);
        
        if (decryptedData) {
            QString decryptedString = QString::fromUtf8(decryptedData);
            PRINTF_LOG("Successfully decrypted data: %s\n", decryptedString.toUtf8().constData());
            LOG_CLIENT_INFO("Successfully decrypted server response");
            emit dataReceived(decryptedString);
            free(decryptedData);
        } else {
            PRINTF_LOG("✗ Failed to decrypt server response\n");
            LOG_CLIENT_ERROR("Failed to decrypt server response");
            emit dataReceived("Şifreli veri çözülemedi");
        }
    } else if (dataString.startsWith("PLAIN:")) {
        // Plain text veri
        QString plainData = dataString.mid(6); // "PLAIN:" = 6 karakter
        PRINTF_LOG("Plain text data received: %s\n", plainData.toUtf8().constData());
        LOG_CLIENT_INFO("Received plain text data from server");
        emit dataReceived(plainData);
    } else {
        // Ham veri (muhtemelen eski format)
        PRINTF_LOG("Raw/Legacy data received: %s\n", dataString.toUtf8().constData());
        LOG_CLIENT_INFO("Received raw data from server");
        emit dataReceived(dataString);
    }
}

/**
 * @brief Taktik veri JSON'u oluşturur (data.json formatında)
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
    jsonObj["unit_id"] = "BİRİM-01";
    
    // Veri tipini status'a çevir
    QString status;
    if (dataType == "Enemy Contact") {
        status = "Düşman Teması";
    } else if (dataType == "Friendly Unit") {
        status = "Dost Birlik";
    } else if (dataType == "Objective") {
        status = "Hedef";
    } else if (dataType == "Hazard") {
        status = "Tehlike";
    } else {
        status = "Taktik Pozisyon";
    }
    
    jsonObj["status"] = status;
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
 * @param encrypted Şifreli gönderim
 */
void ClientWrapper::sendJsonString(const QString& jsonString, bool encrypted)
{
    if (!isConnected()) {
        PRINTF_LOG("✗ Cannot send JSON string - not connected\n");
        emit dataSendResult(NotConnected, "Sunucuya bağlı değilsiniz");
        return;
    }
    
    if (encrypted && !handshakeCompleted) {
        PRINTF_LOG("✗ ECDH handshake not completed - cannot send encrypted data\n");
        emit dataSendResult(SendError, "ECDH handshake tamamlanmamış - şifreli gönderim yapılamaz");
        logError("ECDH handshake tamamlanmamış");
        return;
    }
    
    try {
        char* protocolMessage = nullptr;
        
        if (encrypted) {
            PRINTF_LOG("Creating encrypted protocol message...\n");
            LOG_CLIENT_INFO("Preparing encrypted JSON transmission");
            
            // encrypted_client.c'deki create_encrypted_protocol_message kullan
            protocolMessage = create_encrypted_protocol_message("tactical_data.json", 
                                                               jsonString.toUtf8().constData(), 
                                                               aesKey);
        } else {
            PRINTF_LOG("Creating normal protocol message...\n");
            LOG_CLIENT_INFO("Preparing normal JSON transmission");
            
            // encrypted_client.c'deki create_normal_protocol_message kullan
            protocolMessage = create_normal_protocol_message("tactical_data.json", 
                                                            jsonString.toUtf8().constData());
        }
        
        if (protocolMessage == nullptr) {
            PRINTF_LOG("✗ Failed to create protocol message\n");
            LOG_CLIENT_ERROR("Failed to create protocol message");
            emit dataSendResult(SendError, "Protokol mesajı oluşturma hatası");
            return;
        }
        
        // Protokol mesajını gönder
        QByteArray messageData(protocolMessage, strlen(protocolMessage));
        
        PRINTF_LOG("Sending protocol message (%d bytes): %.50s...\n", 
                   messageData.size(), protocolMessage);
        LOG_CLIENT_INFO("Transmitting protocol message to server (%d bytes)", messageData.size());
        
        qint64 bytesWritten = tcpSocket->write(messageData);
        if (bytesWritten == -1) {
            PRINTF_LOG("✗ Failed to send protocol message\n");
            LOG_CLIENT_ERROR("Failed to send protocol message");
            emit dataSendResult(SendError, "Protokol mesajı gönderimi hatası");
        } else {
            tcpSocket->flush();
            PRINTF_LOG("✓ Protocol message sent successfully (%lld bytes)\n", bytesWritten);
            LOG_CLIENT_INFO("Protocol message transmitted successfully: %lld bytes", bytesWritten);
            emit dataSendResult(SendSuccess, 
                encrypted ? "Şifreli veri başarıyla gönderildi" : "Veri başarıyla gönderildi");
        }
        
        // Belleği temizle
        free(protocolMessage);
        
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Exception in sendJsonString: %s", e.what());
        emit dataSendResult(SendError, "Veri gönderim hatası");
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
    emit logMessage(message);
}

/**
 * @brief Error log mesajı
 */
void ClientWrapper::logError(const QString& message)
{
    LOG_CLIENT_ERROR(message.toUtf8().constData());
    PRINTF_CLIENT("ERROR: %s\n", message.toUtf8().constData());
    emit logMessage(message);
}

/**
 * @brief Debug log mesajı
 */
void ClientWrapper::logDebug(const QString& message)
{
    LOG_CLIENT_DEBUG(message.toUtf8().constData());
    PRINTF_CLIENT("DEBUG: %s\n", message.toUtf8().constData());
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
    
    // Console client protokolünde ACK mesajı yok, handshake bu noktada tamamlanır
    PRINTF_LOG("✓ ECDH protocol completed, ready for encrypted communication\n");
}
