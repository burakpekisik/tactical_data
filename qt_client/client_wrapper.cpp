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
}

QByteArray decryptAes256Cbc(const QByteArray &cipher, const QByteArray &key, const QByteArray &iv);


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
    , jwtToken("")
    , expectedParts(0)
    , receivedParts(0)
    , isProcessingParts(false)
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

    // --- Parçalı ENCRYPTED_PART yanıtları işle ---
    processEncryptedParts();

    // --- Tek parçalı ENCRYPTED yanıtları işle ---
    processEncryptedResponse();

    // --- Düz metin/legacy mesajları ayıkla ---
    while (!incomingBuffer.isEmpty()) {
        int plainEnd = incomingBuffer.indexOf('\n');
        if (plainEnd == -1) break; // Satır sonu yoksa bekle
        
        QByteArray plainMsg = incomingBuffer.left(plainEnd);
        incomingBuffer.remove(0, plainEnd + 1);
        
        QString msgStr = QString::fromUtf8(plainMsg);
        if (!msgStr.startsWith("ENCRYPTED") && !msgStr.isEmpty()) {
            qDebug() << "[DEBUG] Plain/legacy data received:" << msgStr.left(200);
            emit dataReceived(msgStr);
        }
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
 * @param encrypted Şifreli gönderim seçeneği
 */
void ClientWrapper::sendJsonString(const QString& jsonString, bool encrypted)
{
    qDebug() << "[DEBUG] sendJsonString çağrıldı, jwtToken:" << jwtToken << ", handshakeCompleted:" << handshakeCompleted;
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
    qDebug() << "[DEBUG] sendJsonString, aesKey (ilk 8):" << QByteArray((const char*)aesKey, 8).toHex();
    try {
        // Önce pending klasöründeki eski verileri sırayla gönder
        sendAllPendingJson(encrypted);

        if (!isConnected()) {
            // Gönderilemedi, JSON'u pending klasörüne kaydet
            QDir pendingDir(QCoreApplication::applicationDirPath() + "/pending");
            if (!pendingDir.exists()) pendingDir.mkpath(".");
            QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss_zzz");
            QString fileName = QString("pending_%1.json").arg(timestamp);
            QFile f(pendingDir.filePath(fileName));
            if (f.open(QIODevice::WriteOnly)) {
                QTextStream(&f) << jsonString;
                f.close();
                PRINTF_LOG("Veri gönderilemedi, pending klasörüne kaydedildi: %s\n", qPrintable(fileName));
                emit dataSendResult(SendError, "Bağlantı yok, veri kaydedildi: " + fileName);
            } else {
                emit dataSendResult(SendError, "Veri kaydedilemedi!");
            }
            return;
        }
        char* protocolMessage = nullptr;
        if (encrypted) {
            PRINTF_LOG("Creating encrypted protocol message...\n");
            LOG_CLIENT_INFO("Preparing encrypted JSON transmission");
            qDebug() << "[DEBUG] create_encrypted_protocol_message jwtToken:" << jwtToken;
            protocolMessage = create_encrypted_protocol_message("tactical_data.json", 
                                                               jsonString.toUtf8().constData(), 
                                                               aesKey, 
                                                               jwtToken.toUtf8().constData());
        } else {
            PRINTF_LOG("Creating normal protocol message...\n");
            LOG_CLIENT_INFO("Preparing normal JSON transmission");
            qDebug() << "[DEBUG] create_normal_protocol_message jwtToken:" << jwtToken;
            protocolMessage = create_normal_protocol_message("tactical_data.json", 
                                                            jsonString.toUtf8().constData(), 
                                                            jwtToken.toUtf8().constData());
        }
        if (protocolMessage == nullptr) {
            PRINTF_LOG("✗ Failed to create protocol message\n");
            LOG_CLIENT_ERROR("Failed to create protocol message");
            emit dataSendResult(SendError, "Protokol mesajı oluşturma hatası");
            return;
        }
        QByteArray messageData(protocolMessage, strlen(protocolMessage));
        PRINTF_LOG("Sending protocol message (%d bytes): %.50s...\n", 
                   messageData.size(), protocolMessage);
        LOG_CLIENT_INFO("Transmitting protocol message to server (%d bytes)", messageData.size());
        qint64 bytesWritten = tcpSocket->write(messageData);
        if (bytesWritten == -1) {
            PRINTF_LOG("✗ Failed to send protocol message\n");
            LOG_CLIENT_ERROR("Failed to send protocol message");
            saveJsonToPending(jsonString); // Gönderilemeyen veriyi pending'e kaydet
            emit dataSendResult(SendError, "Protokol mesajı gönderimi hatası, veri kaydedildi");
        } else {
            tcpSocket->flush();
            PRINTF_LOG("✓ Protocol message sent successfully (%lld bytes)\n", bytesWritten);
            LOG_CLIENT_INFO("Protocol message transmitted successfully: %lld bytes", bytesWritten);
            emit dataSendResult(SendSuccess, 
                encrypted ? "Şifreli veri başarıyla gönderildi" : "Veri başarıyla gönderildi");
        }
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

// --- YENİ EKLENEN FONKSIYONLAR ---

/**
 * @brief Admin rapora cevap gönderir
 * @param reportId Rapor ID'si
 * @param message Cevap mesajı
 */
void ClientWrapper::adminReplyToReport(int reportId, const QString& message) {
    if (!isConnected() || !handshakeCompleted) {
        logError("Bağlantı yok veya ECDH tamamlanmamış, admin reply gönderilemez");
        return;
    }
    
    // JSON formatında admin reply mesajı oluştur
    QJsonObject replyObj;
    replyObj["report_id"] = reportId;
    replyObj["msg"] = message;
    replyObj["jwt"] = jwtToken;
    
    QJsonDocument doc(replyObj);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    
    // Şifreli protokol mesajı oluştur
    char* encryptedMsg = create_encrypted_protocol_message("REPLY_REPORT", 
                                                          jsonData.constData(), 
                                                          aesKey, 
                                                          jwtToken.toUtf8().constData());
    if (!encryptedMsg) {
        logError("Admin reply şifreli mesajı oluşturulamadı");
        return;
    }
    
    // Mesajı gönder
    QByteArray msgData(encryptedMsg, strlen(encryptedMsg));
    free(encryptedMsg);
    
    tcpSocket->write(msgData);
    tcpSocket->flush();
    
    logInfo(QString("Admin reply gönderildi: Rapor ID %1").arg(reportId));
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
    char* encryptedMsg = create_encrypted_protocol_message("REPLY_QUERY", 
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
 * @brief Admin bildirimlerini dinlemeyi başlatır
 */
void ClientWrapper::listenForAdminNotifications() {
    if (!isConnected()) {
        logError("Bağlantı yok, admin bildirimleri dinlenemez");
        return;
    }
    
    // Admin notification listen mesajı gönder
    QString notifyCmd = QString("ADMIN_NOTIFY_LISTEN:%1").arg(jwtToken);
    QByteArray cmdData = notifyCmd.toUtf8();
    
    tcpSocket->write(cmdData);
    tcpSocket->flush();
    
    logInfo("Admin bildirim dinleme başlatıldı");
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
    
    // UDP test mesajı gönder
    QByteArray testMsg = "UDP_TEST";
    qint64 sent = udpSocket->writeDatagram(testMsg, QHostAddress(serverHost), serverPort + 1);
    
    if (sent > 0) {
        logInfo("UDP test mesajı gönderildi");
        return true;
    } else {
        logError("UDP test mesajı gönderilemedi");
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
    logInfo("Tüm bağlantı türleri test ediliyor...");
    
    // TCP test
    if (currentType != ConnectionType::TCP) {
        if (connectToServerInternal(serverHost, serverPort, ConnectionType::TCP)) {
            if (trySendJsonInternal(jsonString, encrypted)) {
                logInfo("TCP bağlantı testi başarılı");
                disconnectFromServer();
            }
        }
    }
    
    // UDP test
    if (testUdpConnection()) {
        if (connectUdp(serverHost, serverPort + 1)) {
            QByteArray udpAesKey;
            if (udpEcdhHandshake(udpAesKey)) {
                logInfo("UDP ECDH testi başarılı");
            }
        }
    }
    
    // P2P test
    if (testP2pConnection()) {
        if (connectP2p(serverHost, serverPort + 2)) {
            QByteArray p2pAesKey;
            if (p2pEcdhHandshake(p2pAesKey)) {
                logInfo("P2P ECDH testi başarılı");
            }
        }
    }
    
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
 * @brief Parçalı ENCRYPTED_PART yanıtlarını işler
 */
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
                    qDebug() << "[DEBUG] Decrypt başarılı, JSON:" << QString(plainJson.left(200));
                    
                    QJsonDocument doc = QJsonDocument::fromJson(plainJson);
                    if (doc.isObject()) {
                        QJsonObject obj = doc.object();
                        if (obj.contains("reports") && obj["reports"].isArray()) {
                            int privilege = obj.contains("privilege") ? obj["privilege"].toInt() : 0;
                            emit reportsReceived(obj["reports"].toArray(), privilege);
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
            qDebug() << "[DEBUG] Parçalı decrypt başarılı, JSON:" << QString(plainJson.left(200));
            
            // JSON parse et ve raporları emit et
            QJsonDocument doc = QJsonDocument::fromJson(plainJson);
            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                if (obj.contains("reports") && obj["reports"].isArray()) {
                    int privilege = obj.contains("privilege") ? obj["privilege"].toInt() : 0;
                    emit reportsReceived(obj["reports"].toArray(), privilege);
                    qDebug() << "[DEBUG] Raporlar emit edildi, sayı:" << obj["reports"].toArray().size();
                } else {
                    qDebug() << "[DEBUG] JSON'da reports array bulunamadı";
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
