/**
 * @file mainwindow.cpp
 * @brief Qt tabanlı taktik veri gönderim istemcisi ana pencere implementasyonu
 * @details Bu dosya, harita tabanlı taktik veri gönderim uygulamasının ana pencere
 *          sınıfının implementasyonunu içerir. Qt framework kullanarak GUI bileşenlerini
 *          yönetir ve kullanıcı etkileşimlerini işler.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 */

#include "mainwindow.h"
#include "login_dialog.h"
#include <QApplication>
#include <QMessageBox>
#include <QDateTime>
#include <QStatusBar>
#include <QCheckBox>
#include <QProgressBar>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>

/**
 * @brief MainWindow sınıfının constructor'ı
 * @details Ana pencereyi başlatır, UI bileşenlerini kurar ve başlangıç değerlerini atar.
 *          Pencere boyutunu, başlığını ve minimum boyutlarını ayarlar.
 * @param parent Üst widget (genellikle nullptr)
 */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , centralWidget(nullptr)
    , mainSplitter(nullptr)
    , mapPanel(nullptr)
    , mapWidget(nullptr)
    , controlPanel(nullptr)
    , selectedLatitude(0.0)
    , selectedLongitude(0.0)
    , pointSelected(false)
    , clientWrapper(nullptr)
{
    // Client wrapper oluştur
    clientWrapper = new ClientWrapper(this);
    
    // Client wrapper signals bağla
    connect(clientWrapper, &ClientWrapper::connectionStatusChanged,
            this, &MainWindow::onConnectionStatusChanged);
    connect(clientWrapper, &ClientWrapper::dataSendResult,
            this, &MainWindow::onDataSendResult);
    connect(clientWrapper, &ClientWrapper::dataReceived,
            this, &MainWindow::onDataReceived);
    connect(clientWrapper, &ClientWrapper::logMessage,
            this, &MainWindow::onLogMessage);
    connect(clientWrapper, &ClientWrapper::reportsReceived,
            this, &MainWindow::onReportsReceived);
    connect(clientWrapper, &ClientWrapper::ecdhHandshakeCompleted, this, [this](){
        logTextEdit->append("<b>[INFO]</b> ECDH tamamlandı, otomatik rapor sorgulanıyor...");
        clientWrapper->getReports();
    });
    
    setupUI();
    setWindowTitle("Tactical Data Client - Harita Arayüzü");
    setMinimumSize(1200, 800);
    resize(1400, 900);
    
    // Status bar ekle
    statusBar()->showMessage("Hazır");
}

/**
 * @brief MainWindow sınıfının destructor'ı
 * @details Pencere kapanırken gerekli temizlik işlemlerini yapar.
 *          Qt'nin parent-child sistemi sayesinde otomatik bellek yönetimi sağlanır.
 */
MainWindow::~MainWindow()
{
}

/**
 * @brief Ana kullanıcı arayüzünü kurar
 * @details Tüm UI bileşenlerini oluşturur ve düzenler. Ana splitter ile
 *          harita paneli ve kontrol panelini yan yana yerleştirir.
 * @note Bu fonksiyon constructor'da çağrılır
 */
void MainWindow::setupUI()
{
    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    // Ana splitter
    mainSplitter = new QSplitter(Qt::Horizontal, this);
    
    setupMapPanel();
    setupControlPanel();
    
    // Splitter'a panelleri ekle
    mainSplitter->addWidget(mapPanel);
    mainSplitter->addWidget(controlPanel);
    mainSplitter->setSizes({800, 400});
    
    // Ana layout
    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->addWidget(mainSplitter);
    mainLayout->setContentsMargins(5, 5, 5, 5);
}

/**
 * @brief Harita panelini kurar
 * @details Sol tarafta yer alan harita bölümünü oluşturur. MapWidget'ı ekler
 *          ve koordinat bilgisi için label ekler. Harita tıklama olaylarını dinler.
 * @note Harita widget'ından gelen pointClicked sinyali onMapClicked slot'una bağlanır
 */
void MainWindow::setupMapPanel()
{
    mapPanel = new QWidget();
    mapPanel->setMinimumWidth(600);
    
    QVBoxLayout *mapLayout = new QVBoxLayout(mapPanel);
    
    // Harita widget'ı
    mapWidget = new MapWidget(this);
    connect(mapWidget, &MapWidget::pointClicked, this, &MainWindow::onMapClicked);
    
    // Koordinat bilgisi
    coordinatesLabel = new QLabel("Koordinat seçmek için haritaya tıklayın");
    coordinatesLabel->setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; border: 1px solid #ccc; }");
    
    // Marker görünürlüğünü kontrol eden buton
    toggleMarkersButton = new QPushButton("Rapor Markerlarını Gizle");
    toggleMarkersButton->setCheckable(true);
    toggleMarkersButton->setChecked(true);
    connect(toggleMarkersButton, &QPushButton::toggled, this, [this](bool checked){
        if (mapWidget) {
            QMetaObject::invokeMethod(mapWidget, "setMarkersVisible", Q_ARG(bool, checked));
        }
        toggleMarkersButton->setText(checked ? "Rapor Markerlarını Gizle" : "Rapor Markerlarını Göster");
        logTextEdit->append(QString("<b>[KULLANICI]</b> Markerlar %1").arg(checked ? "gösterildi" : "gizlendi"));
    });
    
    mapLayout->addWidget(mapWidget, 1); // Haritaya genişleme faktörü ekle
    mapLayout->addWidget(coordinatesLabel);
    mapLayout->addWidget(toggleMarkersButton); // Butonu ekle
    mapLayout->setContentsMargins(5, 5, 5, 5);
}

/**
 * @brief Ana kontrol panelini kurar
 * @details Sağ tarafta yer alan kontrol alanını oluşturur. Bağlantı, veri gönderimi
 *          ve log panellerini içerir. Panel genişliğini sınırlar.
 * @note Bu panel sabit genişlikte tutularak haritanın daha geniş görünmesi sağlanır
 */
void MainWindow::setupControlPanel()
{
    controlPanel = new QWidget();
    controlPanel->setMaximumWidth(400);
    controlPanel->setMinimumWidth(350);
    
    QVBoxLayout *controlLayout = new QVBoxLayout(controlPanel);
    
    setupConnectionPanel();
    setupDataPanel();
    setupLogPanel();
    
    controlLayout->addWidget(connectionGroup);
    controlLayout->addWidget(dataGroup);
    controlLayout->addWidget(logGroup);
    controlLayout->setContentsMargins(5, 5, 5, 5);
    
    updateUIState();
}

/**
 * @brief Veri gönderim panelini kurar
 * @details Seçili nokta bilgisi, veri tipi seçimi, mesaj girişi ve gönder butonu
 *          içeren paneli oluşturur. Taktik veri tiplerini combo box'a ekler.
 * @note Gönder butonu sadece hem bağlantı kurulduğunda hem de nokta seçildiğinde aktif olur
 */
void MainWindow::setupDataPanel()
{
    dataGroup = new QGroupBox("Veri Gönderimi");
    QVBoxLayout *dataLayout = new QVBoxLayout(dataGroup);
    
    // Seçili nokta bilgisi
    selectedPointLabel = new QLabel("Seçili Nokta: Henüz seçilmedi");
    selectedPointLabel->setStyleSheet("QLabel { background-color: #e8f4f8; padding: 5px; border: 1px solid #ccc; }");
    
    // Veri tipi seçimi
    QHBoxLayout *typeLayout = new QHBoxLayout();
    typeLayout->addWidget(new QLabel("Veri Tipi:"));
    dataTypeCombo = new QComboBox();
    dataTypeCombo->addItems({"Tactical Position", "Enemy Contact", "Friendly Unit", "Objective", "Hazard"});
    typeLayout->addWidget(dataTypeCombo);
    
    // Mesaj
    QHBoxLayout *messageLayout = new QHBoxLayout();
    messageLayout->addWidget(new QLabel("Mesaj:"));
    messageEdit = new QLineEdit("Tactical data from client");
    messageLayout->addWidget(messageEdit);
    
    // Gönder butonu
    sendButton = new QPushButton("Veri Gönder");
    sendButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }");
    sendButton->setEnabled(false);
    
    // Şifreleme checkbox
    encryptionCheckBox = new QCheckBox("Şifreli Gönderim");
    encryptionCheckBox->setChecked(true);
    encryptionCheckBox->setToolTip("Veriyi AES256 ile şifreler");
    
    // Progress bar
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    progressBar->setRange(0, 0); // Belirsiz ilerleme
    
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::onSendData);
    
    dataLayout->addWidget(selectedPointLabel);
    dataLayout->addLayout(typeLayout);
    dataLayout->addLayout(messageLayout);
    dataLayout->addWidget(encryptionCheckBox);
    dataLayout->addWidget(sendButton);
    dataLayout->addWidget(progressBar);
}

/**
 * @brief İşlem geçmişi panelini kurar
 * @details Kullanıcı işlemlerini ve sistem olaylarını kaydeden log alanını oluşturur.
 *          Salt okunur metin editörü kullanır ve başlangıç mesajını ekler.
 * @note Log mesajları zaman damgası ile birlikte kaydedilir
 */
void MainWindow::setupLogPanel()
{
    logGroup = new QGroupBox("İşlem Geçmişi");
    QVBoxLayout *logLayout = new QVBoxLayout(logGroup);
    
    logTextEdit = new QTextEdit();
    logTextEdit->setMaximumHeight(200);
    logTextEdit->setReadOnly(true);
    logTextEdit->append("Uygulama başlatıldı - " + QDateTime::currentDateTime().toString());
    
    logLayout->addWidget(logTextEdit);
}

/**
 * @brief Sunucu bağlantı panelini kurar
 * @details Sunucu adresi, port girişi, bağlantı butonları ve durum göstergesini
 *          içeren paneli oluşturur. Bağlantı durumu ve mesajına göre bileşenleri etkinleştirir/devre dışı bırakır.
 * @note Bağlantı kurulduğunda adres ve port alanları düzenlenemez hale gelir
 */
void MainWindow::setupConnectionPanel()
{
    connectionGroup = new QGroupBox("Sunucu Bağlantısı");
    QVBoxLayout *connLayout = new QVBoxLayout(connectionGroup);
    
    // Sunucu adresi
    QHBoxLayout *addressLayout = new QHBoxLayout();
    addressLayout->addWidget(new QLabel("Adres:"));
    serverAddressEdit = new QLineEdit("127.0.0.1");
    addressLayout->addWidget(serverAddressEdit);
    
    // Port
    QHBoxLayout *portLayout = new QHBoxLayout();
    portLayout->addWidget(new QLabel("Port:"));
    serverPortSpin = new QSpinBox();
    serverPortSpin->setRange(1, 65535);
    serverPortSpin->setValue(8080);
    portLayout->addWidget(serverPortSpin);
    
    // Bağlantı butonları
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    connectButton = new QPushButton("Bağlan");
    disconnectButton = new QPushButton("Bağlantıyı Kes");
    buttonLayout->addWidget(connectButton);
    buttonLayout->addWidget(disconnectButton);
    
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectToServer);
    connect(disconnectButton, &QPushButton::clicked, this, &MainWindow::onDisconnectFromServer);
    
    // Bağlantı durumu
    connectionStatusLabel = new QLabel("Bağlantı Durumu: Bağlı Değil");
    connectionStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    
    connLayout->addLayout(addressLayout);
    connLayout->addLayout(portLayout);
    connLayout->addLayout(buttonLayout);
    connLayout->addWidget(connectionStatusLabel);
}

/**
 * @brief Harita tıklama olayını işler
 * @details Kullanıcı haritada bir noktaya tıkladığında çağrılır. Seçili koordinatları
 *          günceller, UI'daki bilgileri yeniler ve gönder butonunun durumunu kontrol eder.
 * @param latitude Seçilen noktanın enlem koordinatı
 * @param longitude Seçilen noktanın boylam koordinatı
 * @note Bu slot MapWidget'ın pointClicked sinyali ile bağlıdır
 */
void MainWindow::onMapClicked(double latitude, double longitude)
{
    selectedLatitude = latitude;
    selectedLongitude = longitude;
    pointSelected = true;
    
    QString coordText = QString("Seçili Nokta: %1, %2")
                       .arg(latitude, 0, 'f', 6)
                       .arg(longitude, 0, 'f', 6);
    
    selectedPointLabel->setText(coordText);
    coordinatesLabel->setText(QString("Koordinat: %1, %2").arg(latitude, 0, 'f', 6).arg(longitude, 0, 'f', 6));
    
    // UI durumunu güncelle
    updateUIState();
    
    logTextEdit->append(QString("Nokta seçildi: %1, %2 - %3")
                       .arg(latitude, 0, 'f', 6)
                       .arg(longitude, 0, 'f', 6)
                       .arg(QDateTime::currentDateTime().toString()));
}

/**
 * @brief Veri gönderim işlemini gerçekleştirir
 * @details Seçili koordinat, veri tipi ve mesaj bilgilerini alarak sunucuya gönderir.
 *          Bağlantı durumu ve nokta seçimi kontrolü yapar. Başarılı/başarısız durumu bildirir.
 * @note Şu anda sadece simülasyon yapılmaktadır, gerçek sunucu bağlantısı eklenmeli
 * @warning Bağlantı kurulmamışsa veya nokta seçilmemişse uyarı mesajı gösterir
 */
void MainWindow::onSendData()
{
    if (!pointSelected) {
        QMessageBox::warning(this, "Uyarı", "Önce haritadan bir nokta seçin!");
        return;
    }

    QString dataType = dataTypeCombo->currentText();
    QString message = messageEdit->text();
    bool encrypted = encryptionCheckBox->isChecked();

    // Progress bar göster
    progressBar->setVisible(true);
    sendButton->setEnabled(false);

    // Bağlantı varsa normal gönder, yoksa fallback dene
    if (clientWrapper->isConnected()) {
        clientWrapper->sendTacticalData(selectedLatitude, selectedLongitude,
                                       dataType, message, encrypted);
    } else {
        // Fallback ile gönderim
        QString jsonString = clientWrapper->createTacticalDataJson(selectedLatitude, selectedLongitude, dataType, message);
        clientWrapper->trySendWithFallback(jsonString, encrypted);
        logTextEdit->append("[FALLBACK] Bağlantı yok, fallback ile gönderim denendi.");
    }
}

/**
 * @brief Sunucuya bağlantı kurar
 * @details Kullanıcının girdiği adres ve port bilgilerini alarak sunucuya bağlanmaya çalışır.
 *          Bağlantı durumunu günceller ve log'a kaydeder.
 * @note Şu anda sadece simülasyon yapılmaktadır, gerçek bağlantı implementasyonu eklenmeli
 * @todo Gerçek TCP/UDP bağlantı kodu eklenmeli, encrypted_client.c kodu entegre edilmeli
 */
void MainWindow::onConnectToServer()
{
    QString address = serverAddressEdit->text();
    int port = serverPortSpin->value();
    
    if (address.isEmpty()) {
        QMessageBox::warning(this, "Uyarı", "Sunucu adresi boş olamaz!");
        return;
    }
    
    clientWrapper->connectToServer(address, port);
}

/**
 * @brief Sunucu bağlantısını keser
 * @details Mevcut sunucu bağlantısını sonlandırır, bağlantı durumunu günceller
 *          ve log'a kaydeder. UI bileşenlerinin durumlarını resetler.
 * @note Bağlantı kesildikten sonra veri gönderimi devre dışı kalır
 */
void MainWindow::onDisconnectFromServer()
{
    clientWrapper->disconnectFromServer();
}

/**
 * @brief Bağlantı durumu değiştiğinde çağrılır
 */
void MainWindow::onConnectionStatusChanged(ClientWrapper::ConnectionStatus status, const QString& message)
{
    switch (status) {
        case ClientWrapper::Disconnected:
            connectionStatusLabel->setText("Bağlantı Durumu: Bağlı Değil");
            connectionStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
            break;
        case ClientWrapper::Connecting:
            connectionStatusLabel->setText("Bağlantı Durumu: Bağlanıyor...");
            connectionStatusLabel->setStyleSheet("QLabel { color: orange; font-weight: bold; }");
            break;
        case ClientWrapper::Connected:
            connectionStatusLabel->setText("Bağlantı Durumu: Bağlı");
            connectionStatusLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
            break;
        case ClientWrapper::Error:
            connectionStatusLabel->setText("Bağlantı Durumu: Hata");
            connectionStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
            break;
    }
    
    updateUIState();
    showStatusMessage(message);
    
    // Sadece GUI mesajını ekle, log formatı zaten client_wrapper'da yapılıyor
    logTextEdit->append(message);
    
    // Bağlantı başarılı olduğunda otomatik rapor sorgula
    if (status == ClientWrapper::Connected) {
        logTextEdit->append("<b>[INFO]</b> Bağlantı sonrası otomatik rapor sorgulanıyor...");
        if (clientWrapper) clientWrapper->getReports();
    }
}

/**
 * @brief Veri gönderim sonucunda çağrılır
 */
void MainWindow::onDataSendResult(ClientWrapper::SendResult result, const QString& message)
{
    // Progress bar gizle
    progressBar->setVisible(false);
    updateUIState();
    
    switch (result) {
        case ClientWrapper::SendSuccess:
            QMessageBox::information(this, "Başarılı", message);
            showStatusMessage(message, 3000);
            // Veri gönderimi başarılıysa raporları tekrar sorgula
            if (clientWrapper) clientWrapper->getReports();
            break;
        case ClientWrapper::SendError:
        case ClientWrapper::NotConnected:
        case ClientWrapper::InvalidData:
            QMessageBox::warning(this, "Hata", message);
            showStatusMessage(message, 5000);
            break;
    }
    
    // Sadece GUI mesajını ekle, log formatı zaten client_wrapper'da yapılıyor
    logTextEdit->append(message);
}

/**
 * @brief Sunucudan veri alındığında çağrılır
 */
void MainWindow::onDataReceived(const QString& data)
{
    logTextEdit->append(QString("Sunucudan veri: %1").arg(data));
    showStatusMessage("Sunucudan veri alındı");
}

/**
 * @brief Log mesajı alındığında çağrılır
 */
void MainWindow::onLogMessage(const QString& message)
{
    // Qt GUI'de sadece mesajı göster, log formatlama zaten C kodunda yapılıyor
    logTextEdit->append(message);
}

/**
 * @brief Raporlar alındığında çağrılır
 */
void MainWindow::onReportsReceived(const QJsonArray& reports)
{
    logTextEdit->append("<b>[RAPOR]</b> Sunucudan rapor listesi alındı. Toplam: " + QString::number(reports.size()));
    if (!mapWidget) return;
    QMetaObject::invokeMethod(mapWidget, "clearMapItems");
    for (const QJsonValue& val : reports) {
        if (!val.isObject()) continue;
        QJsonObject obj = val.toObject();
        double lat = obj.value("latitude").toDouble();
        double lon = obj.value("longitude").toDouble();
        QString desc = obj.value("description").toString();
        QString status = obj.value("status").toString();
        int id = obj.value("id").toInt();
        qint64 timestamp = obj.value("timestamp").toVariant().toLongLong();
        QString logMsg = QString("Marker eklendi: [%1, %2] - %3").arg(lat, 0, 'f', 6).arg(lon, 0, 'f', 6).arg(desc);
        logTextEdit->append(logMsg);
        QMetaObject::invokeMethod(mapWidget, "addMarker",
            Q_ARG(double, lat), Q_ARG(double, lon), Q_ARG(QString, desc), Q_ARG(QString, status), Q_ARG(int, id), Q_ARG(qint64, timestamp), Q_ARG(bool, false));
    }
}

/**
 * @brief UI durumunu günceller
 */
void MainWindow::updateUIState()
{
    bool connected = clientWrapper->isConnected();
    bool connecting = (clientWrapper->getConnectionStatus() == ClientWrapper::Connecting);
    
    // Bağlantı kontrolleri
    connectButton->setEnabled(!connected && !connecting);
    disconnectButton->setEnabled(connected);
    serverAddressEdit->setEnabled(!connected && !connecting);
    serverPortSpin->setEnabled(!connected && !connecting);
    
    // Veri gönderim kontrolleri
    // sendButton her zaman pointSelected ve progressBar'a göre aktif olsun (bağlantı olmasa da fallback için)
    sendButton->setEnabled(pointSelected && !progressBar->isVisible());
    dataTypeCombo->setEnabled(true);
    messageEdit->setEnabled(true);
    encryptionCheckBox->setEnabled(true);
}

/**
 * @brief Status bar'da mesaj gösterir
 */
void MainWindow::showStatusMessage(const QString& message, int timeout)
{
    statusBar()->showMessage(message, timeout);
}
