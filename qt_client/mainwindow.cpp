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
#include <QScrollArea>
#include <QFrame>
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
    connect(clientWrapper, &ClientWrapper::fallbackTestResult,
            this, &MainWindow::onFallbackTestResult);
    // Admin reply signal'ları
    connect(clientWrapper, &ClientWrapper::dataSuccess, this, [this](const QString& message) {
        logTextEdit->append(QString("<span style='color: #27ae60;'><b>[BAŞARILI]</b></span> %1").arg(message));
    });
    connect(clientWrapper, &ClientWrapper::dataInfo, this, [this](const QString& message) {
        logTextEdit->append(QString("<span style='color: #3498db;'><b>[BİLGİ]</b></span> %1").arg(message));
    });
    connect(clientWrapper, &ClientWrapper::dataError, this, [this](const QString& message) {
        logTextEdit->append(QString("<span style='color: #e74c3c;'><b>[HATA]</b></span> %1").arg(message));
    });
    connect(clientWrapper, &ClientWrapper::ecdhHandshakeCompleted, this, [this](){
        logTextEdit->append("<b>[INFO]</b> ECDH tamamlandı, otomatik rapor sorgulanıyor...");
        clientWrapper->getReports();
        
        // Bekleyen admin reply'ları gönder
        QTimer::singleShot(1000, this, [this]() {
            logTextEdit->append("<b>[INFO]</b> Bekleyen admin reply'lar kontrol ediliyor...");
            clientWrapper->sendAllPendingAdminReplies();
        });
        
        // Login sonrası hemen bağlantı durumunu kontrol et
        QTimer::singleShot(2000, this, [this]() {
            logTextEdit->append("<b>[INFO]</b> Login sonrası bağlantı durumu kontrol ediliyor...");
            onPeriodicConnectionCheck();
        });
    });
    
    // Periyodik bağlantı kontrolü timer'ı
    connectionCheckTimer = new QTimer(this);
    connect(connectionCheckTimer, &QTimer::timeout, this, &MainWindow::onPeriodicConnectionCheck);
    connectionCheckTimer->setInterval(30000); // 30 saniye
    
    // Konum servisleri başlat
    positionSource = QGeoPositionInfoSource::createDefaultSource(this);
    if (positionSource) {
        connect(positionSource, &QGeoPositionInfoSource::positionUpdated,
                this, &MainWindow::onPositionUpdated);
        connect(positionSource, &QGeoPositionInfoSource::errorOccurred,
                this, &MainWindow::onPositionError);
        positionSource->setUpdateInterval(5000); // 5 saniye güncelleme
    }
    
    setupUI();
    setWindowTitle("Tactical Data Client - Harita Arayüzü");
    setMinimumSize(1200, 800);
    resize(1400, 1000);
    
    // Status bar ekle
    statusBar()->showMessage("Hazır");
    
    // Otomatik durum kontrolünü başlat (UI kurulumundan sonra)
    QTimer::singleShot(1000, this, [this]() {
        // UI tamamen yüklenince otomatik kontrolü başlat
        if (autoCheckEnabled) {
            connectionCheckTimer->start();
            logTextEdit->append("<b>[INFO]</b> Otomatik bağlantı kontrolü başlatıldı (30 saniye aralık)");
        }
    });
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
    setupControlPanel(); // Bu zaten admin ve fallback panellerini içinde kuruyor
    
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
    connect(mapWidget, &MapWidget::markerClicked, this, &MainWindow::onMarkerClicked);
    
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
    
    // Konum bulma butonu
    findLocationButton = new QPushButton("📍 Şu Anki Konumumu Bul");
    findLocationButton->setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; padding: 8px; }");
    connect(findLocationButton, &QPushButton::clicked, this, &MainWindow::onFindMyLocation);
    
    // Mevcut konum bilgisi
    currentLocationLabel = new QLabel("Mevcut Konum: Henüz belirlenmedi");
    currentLocationLabel->setStyleSheet("QLabel { background-color: #E3F2FD; padding: 5px; border: 1px solid #2196F3; border-radius: 3px; }");
    
    // Butonlar için yatay layout
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(toggleMarkersButton);
    buttonLayout->addWidget(findLocationButton);
    
    mapLayout->addWidget(mapWidget, 1); // Haritaya genişleme faktörü ekle
    mapLayout->addWidget(coordinatesLabel);
    mapLayout->addWidget(currentLocationLabel);
    mapLayout->addLayout(buttonLayout);
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
    setupAdminPanel();      // Admin paneli oluştur
    setupFallbackPanel();   // Fallback paneli oluştur  
    setupLogPanel();
    
    controlLayout->addWidget(connectionGroup);
    controlLayout->addWidget(dataGroup);
    controlLayout->addWidget(adminGroup);       // Admin paneli
    controlLayout->addWidget(fallbackGroup);    // Fallback paneli
    controlLayout->addWidget(logGroup);
    controlLayout->setContentsMargins(5, 5, 5, 5);

    // Admin mod anahtarlama butonunu başta oluştur, gizli tut
    modeSwitchButton = new QPushButton("Dönüt Yap Modu", this);
    modeSwitchButton->setCheckable(true);
    modeSwitchButton->setChecked(false);
    modeSwitchButton->hide();
    connect(modeSwitchButton, &QPushButton::toggled, this, [this](bool checked){
        currentMode = checked ? ReplyMode : SendMode;
        modeSwitchButton->setText(checked ? "Veri Gönder Modu" : "Dönüt Yap Modu");
        logTextEdit->append(QString("<b>[MOD]</b> %1").arg(checked ? "Dönüt Yap Modu" : "Veri Gönder Modu"));
        // Mod değişince QML'e marker ekleme izni gönder
        if (mapWidget) {
            QQuickWidget* quickWidget = mapWidget->findChild<QQuickWidget*>();
            if (quickWidget) {
                quickWidget->rootContext()->setContextProperty("allowAddMarker", currentMode == SendMode);
            }
        }
        // Veri Gönderimi panelini sadece SendMode'da aktif et
        if (dataGroup) {
            dataGroup->setEnabled(currentMode == SendMode);
        }
    });
    controlLayout->addWidget(modeSwitchButton);

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
    dataGroup->setEnabled(currentMode == SendMode); // Uygulama başında da doğru modda başlasın
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
    if (currentMode == ReplyMode) {
        // Dönüt modunda harita boşluğuna tıklanınca hiçbir şey yapma
        return;
    }
    // SendMode: Nokta eklenebilir
    selectedLatitude = latitude;
    selectedLongitude = longitude;
    pointSelected = true;
    QString coordText = QString("Seçili Nokta: %1, %2")
                       .arg(latitude, 0, 'f', 6)
                       .arg(longitude, 0, 'f', 6);
    selectedPointLabel->setText(coordText);
    updateUIState();
}

void MainWindow::onMarkerClicked(int id, double latitude, double longitude)
{
    if (currentMode == ReplyMode) {
        // Admin dönüt modunda: Dönüt gönder menüsü aç
        showAdminReplyDialog(id, latitude, longitude);
    } else {
        // Normal modda: Bu marker için mevcut reply'ları göster
        showMarkerRepliesDialog(id, latitude, longitude);
    }
}

void MainWindow::showAdminReplyDialog(int id, double latitude, double longitude)
{
    QDialog dialog(this);
    dialog.setWindowTitle(QString("Marker %1 - Admin İşlemleri").arg(id));
    dialog.setModal(true);
    dialog.resize(650, 450);
    
    QVBoxLayout* mainLayout = new QVBoxLayout(&dialog);
    
    // Marker bilgileri
    QLabel* info = new QLabel(QString("Marker ID: %1\nKoordinat: %2, %3").arg(id).arg(latitude, 0, 'f', 6).arg(longitude, 0, 'f', 6));
    info->setStyleSheet("font-weight: bold; color: #2c3e50; padding: 10px; background-color: #ecf0f1; border-radius: 4px; margin-bottom: 10px;");
    mainLayout->addWidget(info);
    
    // Tab widget oluştur
    QTabWidget* tabWidget = new QTabWidget();
    tabWidget->setStyleSheet("QTabWidget::pane { border: 1px solid #bdc3c7; } QTabBar::tab { padding: 8px 16px; margin-right: 2px; } QTabBar::tab:selected { background-color: #3498db; color: white; }");
    
    // Tab 1: Mevcut Cevapları Görüntüle
    QWidget* repliesTab = new QWidget();
    QVBoxLayout* repliesTabLayout = new QVBoxLayout(repliesTab);
    
    QScrollArea* scrollArea = new QScrollArea();
    QWidget* repliesWidget = new QWidget();
    QVBoxLayout* repliesLayout = new QVBoxLayout(repliesWidget);
    
    // Yükleniyor mesajı
    QLabel* loadingLabel = new QLabel("Admin cevapları yükleniyor...");
    loadingLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 20px; text-align: center;");
    loadingLabel->setAlignment(Qt::AlignCenter);
    repliesLayout->addWidget(loadingLabel);
    
    scrollArea->setWidget(repliesWidget);
    scrollArea->setWidgetResizable(true);
    scrollArea->setStyleSheet("QScrollArea { border: 1px solid #bdc3c7; border-radius: 4px; }");
    repliesTabLayout->addWidget(scrollArea);
    
    // Yenile butonu
    QPushButton* refreshBtn = new QPushButton("Yenile");
    refreshBtn->setStyleSheet("QPushButton { background-color: #3498db; color: white; border: none; padding: 8px 16px; border-radius: 4px; } QPushButton:hover { background-color: #2980b9; }");
    repliesTabLayout->addWidget(refreshBtn);
    
    tabWidget->addTab(repliesTab, "Mevcut Cevaplar");
    
    // Tab 2: Yeni Cevap Gönder
    QWidget* sendReplyTab = new QWidget();
    QVBoxLayout* sendReplyLayout = new QVBoxLayout(sendReplyTab);
    
    QLabel* instructionLabel = new QLabel("Bu rapor için admin dönütü gönderebilirsiniz:");
    instructionLabel->setStyleSheet("color: #7f8c8d; margin-bottom: 15px; font-size: 14px;");
    sendReplyLayout->addWidget(instructionLabel);
    
    QTextEdit* replyTextEdit = new QTextEdit();
    replyTextEdit->setPlaceholderText("Dönüt mesajınızı buraya yazın...\n\nDetaylı açıklamalar için birden fazla satır kullanabilirsiniz.");
    replyTextEdit->setStyleSheet("padding: 12px; border: 2px solid #bdc3c7; border-radius: 6px; font-size: 12px; min-height: 120px;");
    sendReplyLayout->addWidget(replyTextEdit);
    
    // Karakter sayacı
    QLabel* charCountLabel = new QLabel("0 karakter");
    charCountLabel->setStyleSheet("color: #7f8c8d; font-size: 11px; margin-top: 5px;");
    connect(replyTextEdit, &QTextEdit::textChanged, [replyTextEdit, charCountLabel]() {
        int charCount = replyTextEdit->toPlainText().length();
        charCountLabel->setText(QString("%1 karakter").arg(charCount));
        if (charCount > 500) {
            charCountLabel->setStyleSheet("color: #e74c3c; font-size: 11px; margin-top: 5px;");
        } else {
            charCountLabel->setStyleSheet("color: #7f8c8d; font-size: 11px; margin-top: 5px;");
        }
    });
    sendReplyLayout->addWidget(charCountLabel);
    
    sendReplyLayout->addStretch();
    
    QPushButton* sendBtn = new QPushButton("Dönütü Gönder");
    sendBtn->setStyleSheet("QPushButton { background-color: #27ae60; color: white; border: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; } QPushButton:hover { background-color: #2ecc71; }");
    sendReplyLayout->addWidget(sendBtn);
    
    tabWidget->addTab(sendReplyTab, "Yeni Cevap Gönder");
    
    mainLayout->addWidget(tabWidget);
    
    // Ana butonlar
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* closeBtn = new QPushButton("Kapat");
    closeBtn->setStyleSheet("QPushButton { background-color: #95a5a6; color: white; border: none; padding: 10px 20px; border-radius: 4px; } QPushButton:hover { background-color: #7f8c8d; }");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeBtn);
    mainLayout->addLayout(buttonLayout);
    
    // Signal bağlantıları
    connect(closeBtn, &QPushButton::clicked, &dialog, &QDialog::accept);
    
    // Dönüt gönder butonu
    connect(sendBtn, &QPushButton::clicked, [&dialog, replyTextEdit, id, this](){
        QString message = replyTextEdit->toPlainText().trimmed();
        
        if (message.isEmpty()) {
            QMessageBox::warning(&dialog, "Uyarı", "Dönüt mesajı boş olamaz!");
            return;
        }
        
        if (message.length() > 500) {
            QMessageBox::warning(&dialog, "Uyarı", "Dönüt mesajı 500 karakterden uzun olamaz!");
            return;
        }
        
        // Admin reply gönder
        logTextEdit->append(QString("<span style='color: #e67e22;'><b>[ADMIN REPLY]</b></span> Marker ID %1 için dönüt gönderiliyor...").arg(id));
        
        if (clientWrapper) {
            clientWrapper->adminReplyToReport(id, message);
        }
        
        // Mesajı temizle ve başarı mesajı göster
        replyTextEdit->clear();
        QMessageBox::information(&dialog, "Bilgi", "Dönüt mesajı gönderildi!");
    });
    
    // Reply'ları alma signal'ını bağla
    QMetaObject::Connection replyConnection = connect(clientWrapper, &ClientWrapper::reportRepliesReceived, 
        [id, repliesLayout, loadingLabel](int reportId, const QJsonArray& replies) {
            // Eski widget'ları temizle
            QLayoutItem* item;
            while ((item = repliesLayout->takeAt(0)) != nullptr) {
                delete item->widget();
                delete item;
            }
            
            // Bu marker'a ait reply'ları filtrele
            QJsonArray relevantReplies;
            for (const QJsonValue& replyVal : replies) {
                QJsonObject reply = replyVal.toObject();
                if (reply["report_id"].toInt() == id) {
                    relevantReplies.append(replyVal);
                }
            }
            
            if (relevantReplies.isEmpty()) {
                QLabel* noRepliesLabel = new QLabel("Bu marker için henüz admin cevabı bulunmuyor.");
                noRepliesLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 20px; text-align: center;");
                noRepliesLabel->setAlignment(Qt::AlignCenter);
                repliesLayout->addWidget(noRepliesLabel);
            } else {
                for (const QJsonValue& replyVal : relevantReplies) {
                    QJsonObject reply = replyVal.toObject();
                    
                    QFrame* replyFrame = new QFrame();
                    replyFrame->setStyleSheet("QFrame { background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; margin: 5px; }");
                    
                    QVBoxLayout* replyLayout = new QVBoxLayout(replyFrame);
                    
                    // Admin bilgisi ve tarih
                    QString adminInfo = QString("Admin: %1").arg(reply["admin_name"].toString("Bilinmeyen"));
                    
                    // Timestamp'i okunabilir formata çevir
                    qint64 timestamp = reply["timestamp"].toVariant().toLongLong();
                    if (timestamp > 0) {
                        QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
                        QString formattedDate = dateTime.toString("dd-MM-yyyy hh:mm:ss");
                        adminInfo += QString(" - %1").arg(formattedDate);
                    }
                    
                    QLabel* adminLabel = new QLabel(adminInfo);
                    adminLabel->setStyleSheet("font-weight: bold; color: #495057; margin-bottom: 5px;");
                    replyLayout->addWidget(adminLabel);
                    
                    // Cevap mesajı
                    QString replyMsg = reply["message"].toString();
                    QLabel* msgLabel = new QLabel(replyMsg);
                    msgLabel->setStyleSheet("color: #212529; padding: 12px; background-color: white; border-radius: 4px; border: 1px solid #e9ecef;");
                    msgLabel->setWordWrap(true);
                    replyLayout->addWidget(msgLabel);
                    
                    repliesLayout->addWidget(replyFrame);
                }
            }
            
            repliesLayout->addStretch();
        });
    
    // Refresh butonuna basınca yeniden sorgu
    connect(refreshBtn, &QPushButton::clicked, [this, id, loadingLabel, repliesLayout]() {
        // Önce loading mesajını göster
        QLayoutItem* item;
        while ((item = repliesLayout->takeAt(0)) != nullptr) {
            delete item->widget();
            delete item;
        }
        
        QLabel* newLoadingLabel = new QLabel("Admin cevapları yenileniyor...");
        newLoadingLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 20px; text-align: center;");
        newLoadingLabel->setAlignment(Qt::AlignCenter);
        repliesLayout->addWidget(newLoadingLabel);
        
        if (clientWrapper) {
            clientWrapper->queryRepliesForReport(id);
        }
    });
    
    // Dialog kapanınca connection'ı kaldır
    connect(&dialog, &QDialog::finished, [replyConnection]() {
        QObject::disconnect(replyConnection);
    });
    
    // İlk sorguyu başlat
    if (clientWrapper) {
        clientWrapper->queryRepliesForReport(id);
    }
    
    dialog.exec();
}

void MainWindow::showMarkerRepliesDialog(int id, double latitude, double longitude)
{
    QDialog dialog(this);
    dialog.setWindowTitle(QString("Marker %1 - Admin Cevapları").arg(id));
    dialog.setModal(true);
    dialog.resize(600, 400);
    
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    
    // Marker bilgileri
    QLabel* info = new QLabel(QString("Marker ID: %1\nKoordinat: %2, %3").arg(id).arg(latitude, 0, 'f', 6).arg(longitude, 0, 'f', 6));
    info->setStyleSheet("font-weight: bold; color: #2c3e50; padding: 10px; background-color: #ecf0f1; border-radius: 4px; margin-bottom: 10px;");
    layout->addWidget(info);
    
    // Cevaplar için scroll area
    QScrollArea* scrollArea = new QScrollArea();
    QWidget* repliesWidget = new QWidget();
    QVBoxLayout* repliesLayout = new QVBoxLayout(repliesWidget);
    
    // Yükleniyor mesajı
    QLabel* loadingLabel = new QLabel("Admin cevapları yükleniyor...");
    loadingLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 20px; text-align: center;");
    loadingLabel->setAlignment(Qt::AlignCenter);
    repliesLayout->addWidget(loadingLabel);
    
    scrollArea->setWidget(repliesWidget);
    scrollArea->setWidgetResizable(true);
    scrollArea->setStyleSheet("QScrollArea { border: 1px solid #bdc3c7; border-radius: 4px; }");
    layout->addWidget(scrollArea);
    
    // Yenile butonu
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* refreshBtn = new QPushButton("Yenile");
    refreshBtn->setStyleSheet("QPushButton { background-color: #3498db; color: white; border: none; padding: 8px 16px; border-radius: 4px; } QPushButton:hover { background-color: #2980b9; }");
    QPushButton* closeBtn = new QPushButton("Kapat");
    closeBtn->setStyleSheet("QPushButton { background-color: #95a5a6; color: white; border: none; padding: 8px 16px; border-radius: 4px; } QPushButton:hover { background-color: #7f8c8d; }");
    
    buttonLayout->addWidget(refreshBtn);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeBtn);
    layout->addLayout(buttonLayout);
    
    // Signal bağlantıları
    connect(closeBtn, &QPushButton::clicked, &dialog, &QDialog::accept);
    
    // Reply'ları alma signal'ını bağla
    QMetaObject::Connection replyConnection = connect(clientWrapper, &ClientWrapper::reportRepliesReceived, 
        [&dialog, repliesLayout, loadingLabel, id](int reportId, const QJsonArray& replies) {
            // Gelen reply'ları filtrele (sadece bu marker'a ait olanları göster)
            QJsonArray filteredReplies;
            for (const QJsonValue& replyVal : replies) {
                QJsonObject reply = replyVal.toObject();
                int replyReportId = reply["report_id"].toInt();
                if (replyReportId == id) {
                    filteredReplies.append(replyVal);
                }
            }
            
            // Eski widget'ları temizle
            QLayoutItem* item;
            while ((item = repliesLayout->takeAt(0)) != nullptr) {
                delete item->widget();
                delete item;
            }
            
            if (filteredReplies.isEmpty()) {
                QLabel* noRepliesLabel = new QLabel("Bu marker için henüz admin cevabı bulunmuyor.");
                noRepliesLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 20px; text-align: center;");
                noRepliesLabel->setAlignment(Qt::AlignCenter);
                repliesLayout->addWidget(noRepliesLabel);
            } else {
                for (const QJsonValue& replyVal : filteredReplies) {
                    QJsonObject reply = replyVal.toObject();
                    
                    QFrame* replyFrame = new QFrame();
                    replyFrame->setStyleSheet("QFrame { background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; margin: 5px; }");
                    
                    QVBoxLayout* replyLayout = new QVBoxLayout(replyFrame);
                    
                    // Admin bilgisi ve tarih
                    QString adminInfo = QString("Admin ID: %1").arg(reply["user_id"].toInt());
                    qint64 timestamp = reply["timestamp"].toVariant().toLongLong();
                    if (timestamp > 0) {
                        QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
                        adminInfo += QString(" - %1").arg(dateTime.toString("dd-MM-yyyy hh:mm:ss"));
                    }
                    
                    QLabel* adminLabel = new QLabel(adminInfo);
                    adminLabel->setStyleSheet("font-weight: bold; color: #495057; margin-bottom: 5px;");
                    replyLayout->addWidget(adminLabel);
                    
                    // Cevap mesajı
                    QString replyMsg = reply["message"].toString();
                    QLabel* msgLabel = new QLabel(replyMsg);
                    msgLabel->setStyleSheet("color: #212529; padding: 8px; background-color: white; border-radius: 4px; border: 1px solid #e9ecef;");
                    msgLabel->setWordWrap(true);
                    replyLayout->addWidget(msgLabel);
                    
                    repliesLayout->addWidget(replyFrame);
                }
            }
            
            repliesLayout->addStretch();
        });
    
    // Refresh butonuna basınca yeniden sorgu
    connect(refreshBtn, &QPushButton::clicked, [this, id, loadingLabel, repliesLayout]() {
        // Önce loading mesajını göster
        QLayoutItem* item;
        while ((item = repliesLayout->takeAt(0)) != nullptr) {
            delete item->widget();
            delete item;
        }
        
        QLabel* newLoadingLabel = new QLabel("Admin cevapları yenileniyor...");
        newLoadingLabel->setStyleSheet("color: #7f8c8d; font-style: italic; padding: 20px; text-align: center;");
        newLoadingLabel->setAlignment(Qt::AlignCenter);
        repliesLayout->addWidget(newLoadingLabel);
        
        if (clientWrapper) {
            clientWrapper->queryRepliesForReport(id);
        }
    });
    
    // Dialog kapanınca connection'ı kaldır
    connect(&dialog, &QDialog::finished, [replyConnection]() {
        QObject::disconnect(replyConnection);
    });
    
    // İlk sorguyu başlat
    if (clientWrapper) {
        clientWrapper->queryRepliesForReport(id);
    }
    
    dialog.exec();
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
void MainWindow::onReportsReceived(const QJsonArray& reports, int privilege)
{
    qDebug() << "[DEBUG] onReportsReceived called, privilege:" << privilege << ", reports size:" << reports.size();
    userPrivilege = privilege;
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
    // Admin ise mod switch butonunu göster
    if (userPrivilege == 1 && modeSwitchButton) {
        modeSwitchButton->show();
    } else if (modeSwitchButton) {
        modeSwitchButton->hide();
    }
    qDebug() << "[DEBUG] onReportsReceived END";
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
    
    if (mapWidget) {
        // Mod değişince QML'e marker ekleme izni gönder
        QVariant allowAdd = (currentMode == SendMode);
        mapWidget->findChild<QQuickWidget*>()->rootContext()->setContextProperty("allowAddMarker", allowAdd);
    }
}

/**
 * @brief Admin panel kurulumu
 */
void MainWindow::setupAdminPanel()
{
    adminGroup = new QGroupBox("Admin İşlemleri", this);
    QVBoxLayout *adminLayout = new QVBoxLayout(adminGroup);
    
    // Report ID ve mesaj girişi
    QHBoxLayout *replyLayout = new QHBoxLayout();
    replyLayout->addWidget(new QLabel("Rapor ID:"));
    reportIdSpin = new QSpinBox();
    reportIdSpin->setRange(1, 99999);
    replyLayout->addWidget(reportIdSpin);
    
    replyMessageEdit = new QLineEdit();
    replyMessageEdit->setPlaceholderText("Admin cevabı yazın...");
    replyLayout->addWidget(replyMessageEdit);
    
    adminReplyButton = new QPushButton("Rapora Cevap Ver");
    replyLayout->addWidget(adminReplyButton);
    
    adminLayout->addLayout(replyLayout);
    
    // Diğer admin butonları
    QHBoxLayout *adminButtonsLayout = new QHBoxLayout();
    queryRepliesButton = new QPushButton("Kendi Cevaplarımı Sorgula");
    listenNotificationsButton = new QPushButton("Bildirimleri Dinle");
    
    adminButtonsLayout->addWidget(queryRepliesButton);
    adminButtonsLayout->addWidget(listenNotificationsButton);
    adminLayout->addLayout(adminButtonsLayout);
    
    // Admin log alanı
    adminLogEdit = new QTextEdit();
    adminLogEdit->setMaximumHeight(150);
    adminLogEdit->setPlaceholderText("Admin işlem logları burada görünecek...");
    adminLayout->addWidget(adminLogEdit);
    
    // Varsayılan olarak gizli
    adminGroup->setVisible(false);
    
    // Signal bağlantıları
    connect(adminReplyButton, &QPushButton::clicked, this, &MainWindow::onAdminReplyToReport);
    connect(queryRepliesButton, &QPushButton::clicked, this, &MainWindow::onQueryMyReplies);
    connect(listenNotificationsButton, &QPushButton::clicked, this, &MainWindow::onListenForNotifications);
}

/**
 * @brief Fallback panel kurulumu
 */
void MainWindow::setupFallbackPanel()
{
    fallbackGroup = new QGroupBox("Bağlantı Yönetimi", this);
    QVBoxLayout *fallbackLayout = new QVBoxLayout(fallbackGroup);
    
    // Bağlantı durumu göstergeleri
    QGroupBox *statusGroup = new QGroupBox("Bağlantı Durumları");
    QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);
    
    // TCP durum göstergesi
    QHBoxLayout *tcpStatusLayout = new QHBoxLayout();
    tcpStatusLayout->addWidget(new QLabel("TCP:"));
    tcpStatusLabel = new QLabel("Bilinmiyor");
    tcpStatusLabel->setStyleSheet("QLabel { padding: 4px; border: 1px solid #ccc; border-radius: 3px; background-color: #f0f0f0; }");
    tcpStatusLayout->addWidget(tcpStatusLabel);
    tcpStatusLayout->addStretch();
    statusLayout->addLayout(tcpStatusLayout);
    
    // UDP durum göstergesi
    QHBoxLayout *udpStatusLayout = new QHBoxLayout();
    udpStatusLayout->addWidget(new QLabel("UDP:"));
    udpStatusLabel = new QLabel("Bilinmiyor");
    udpStatusLabel->setStyleSheet("QLabel { padding: 4px; border: 1px solid #ccc; border-radius: 3px; background-color: #f0f0f0; }");
    udpStatusLayout->addWidget(udpStatusLabel);
    udpStatusLayout->addStretch();
    statusLayout->addLayout(udpStatusLayout);
    
    // P2P durum göstergesi
    QHBoxLayout *p2pStatusLayout = new QHBoxLayout();
    p2pStatusLayout->addWidget(new QLabel("P2P:"));
    p2pStatusLabel = new QLabel("Bilinmiyor");
    p2pStatusLabel->setStyleSheet("QLabel { padding: 4px; border: 1px solid #ccc; border-radius: 3px; background-color: #f0f0f0; }");
    p2pStatusLayout->addWidget(p2pStatusLabel);
    p2pStatusLayout->addStretch();
    statusLayout->addLayout(p2pStatusLayout);
    
    fallbackLayout->addWidget(statusGroup);
    
    // Periyodik kontrol ayarları
    QHBoxLayout *periodicLayout = new QHBoxLayout();
    periodicCheckBox = new QCheckBox("Otomatik durum kontrolü (30 saniye)");
    periodicCheckBox->setChecked(true);  // Default olarak açık
    periodicLayout->addWidget(periodicCheckBox);
    fallbackLayout->addLayout(periodicLayout);
    
    // Test butonları
    QHBoxLayout *testLayout = new QHBoxLayout();
    testConnectionsButton = new QPushButton("Tüm Bağlantıları Test Et");
    testLayout->addWidget(testConnectionsButton);
    fallbackLayout->addLayout(testLayout);
    
    // Fallback durum etiketi
    fallbackStatusLabel = new QLabel("Fallback Durumu: Hazır");
    fallbackLayout->addWidget(fallbackStatusLabel);
    
    // Fallback log alanı
    fallbackLogEdit = new QTextEdit();
    fallbackLogEdit->setMaximumHeight(120);
    fallbackLogEdit->setPlaceholderText("Fallback işlem logları burada görünecek...");
    fallbackLayout->addWidget(fallbackLogEdit);
    
    // Signal bağlantıları
    connect(testConnectionsButton, &QPushButton::clicked, this, &MainWindow::onTestConnections);
    connect(periodicCheckBox, &QCheckBox::toggled, this, [this](bool checked) {
        autoCheckEnabled = checked;  // Değişkeni güncelle
        if (checked) {
            connectionCheckTimer->start();
            fallbackLogEdit->append("[INFO] Otomatik durum kontrolü başlatıldı (30 saniye aralık)");
        } else {
            connectionCheckTimer->stop();
            fallbackLogEdit->append("[INFO] Otomatik durum kontrolü durduruldu");
        }
    });
}

/**
 * @brief Admin rapora cevap verme slot'u
 */
void MainWindow::onAdminReplyToReport()
{
    int reportId = reportIdSpin->value();
    QString message = replyMessageEdit->text().trimmed();
    
    if (message.isEmpty()) {
        adminLogEdit->append("<b>[HATA]</b> Cevap mesajı boş olamaz");
        return;
    }
    
    adminLogEdit->append(QString("<b>[INFO]</b> Rapor %1'e cevap gönderiliyor: %2").arg(reportId).arg(message));
    clientWrapper->adminReplyToReport(reportId, message);
    replyMessageEdit->clear();
}

/**
 * @brief Kendi cevapları sorgulama slot'u
 */
void MainWindow::onQueryMyReplies()
{
    adminLogEdit->append("<b>[INFO]</b> Kendi cevaplar sorgulanıyor...");
    clientWrapper->queryMyReplies();
}

/**
 * @brief Bildirim dinleme slot'u
 */
void MainWindow::onListenForNotifications()
{
    adminLogEdit->append("<b>[INFO]</b> Admin bildirimleri dinleniyor...");
    clientWrapper->listenForAdminNotifications();
}

/**
 * @brief Bağlantı testi slot'u
 */
void MainWindow::onTestConnections()
{
    fallbackLogEdit->clear(); // Önceki logları temizle
    fallbackLogEdit->append("<b>[TEST]</b> Bağlantı testleri başlatılıyor...");
    
    QString testJson = clientWrapper->createTacticalDataJson(selectedLatitude, selectedLongitude, 
                                                           "connection_test", "Bağlantı testi");
    clientWrapper->testAllConnectionTypes(testJson, true);
}

/**
 * @brief Admin bildirimi alındığında çağrılan slot
 */
void MainWindow::onAdminNotificationReceived(const QString& notification)
{
    adminLogEdit->append(QString("<b>[BİLDİRİM]</b> %1").arg(notification));
}

/**
 * @brief Reply sorgu sonucu alındığında çağrılan slot
 */
void MainWindow::onReplyQueryResultReceived(const QJsonArray& replies)
{
    adminLogEdit->append(QString("<b>[SORGU]</b> %1 adet cevap bulundu").arg(replies.size()));
    
    for (const QJsonValue& value : replies) {
        QJsonObject reply = value.toObject();
        adminLogEdit->append(QString("- Rapor %1: %2")
                           .arg(reply["report_id"].toInt())
                           .arg(reply["message"].toString()));
    }
}

/**
 * @brief Bağlantı türü değiştiğinde çağrılan slot
 */
void MainWindow::onConnectionTypeChanged(ClientWrapper::ConnectionType type)
{
    QString typeStr;
    switch (type) {
        case ClientWrapper::ConnectionType::TCP: typeStr = "TCP"; break;
        case ClientWrapper::ConnectionType::UDP: typeStr = "UDP"; break;
        case ClientWrapper::ConnectionType::P2P: typeStr = "P2P"; break;
    }
    
    fallbackLogEdit->append(QString("<b>[DEĞİŞİM]</b> Aktif bağlantı türü: %1").arg(typeStr));
}

/**
 * @brief Fallback durumu değiştiğinde çağrılan slot
 */
void MainWindow::onFallbackStatusChanged(const QString& status)
{
    fallbackStatusLabel->setText(QString("Fallback Durumu: %1").arg(status));
    fallbackLogEdit->append(QString("<b>[DURUM]</b> %1").arg(status));
}

/**
 * @brief Fallback test sonucu slot'u
 */
void MainWindow::onFallbackTestResult(const QString& connectionType, bool success, const QString& message)
{
    QString colorStyle;
    QString prefix;
    
    if (connectionType == "INFO") {
        colorStyle = "color: blue; font-weight: bold;";
        prefix = "[BİLGİ]";
    } else if (success) {
        colorStyle = "color: green; font-weight: bold;";
        prefix = QString("[%1 ✓]").arg(connectionType);
        // Başarılı bağlantı durumunu güncelle
        updateConnectionStatus(connectionType, true, "Test başarılı");
    } else {
        colorStyle = "color: red; font-weight: bold;";
        prefix = QString("[%1 ✗]").arg(connectionType);
        // Başarısız bağlantı durumunu güncelle
        updateConnectionStatus(connectionType, false, "Test başarısız");
    }
    
    QString logEntry = QString("<span style='%1'>%2</span> %3")
                       .arg(colorStyle)
                       .arg(prefix)
                       .arg(message);
    
    fallbackLogEdit->append(logEntry);
    
    // Otomatik scroll
    QTextCursor cursor = fallbackLogEdit->textCursor();
    cursor.movePosition(QTextCursor::End);
    fallbackLogEdit->setTextCursor(cursor);
}

/**
 * @brief Periyodik bağlantı kontrolü slot'u
 */
void MainWindow::onPeriodicConnectionCheck()
{
    if (!periodicCheckBox->isChecked()) {
        return; // Checkbox kapalıysa çalışma
    }
    
    fallbackLogEdit->append("[AUTO] Otomatik bağlantı kontrolü başlatılıyor...");
    
    // Test JSON verisi - basit bir test mesajı
    QString testJson = R"({"type":"connection_test","timestamp":")" + 
                      QString::number(QDateTime::currentSecsSinceEpoch()) + R"("})";
    
    // Tüm bağlantı türlerini test et
    clientWrapper->testAllConnectionTypes(testJson, false);
}

/**
 * @brief Bağlantı durumu günceller
 */
void MainWindow::updateConnectionStatus(const QString& connectionType, bool isConnected, const QString& details)
{
    QLabel* statusLabel = nullptr;
    
    if (connectionType == "TCP") {
        statusLabel = tcpStatusLabel;
    } else if (connectionType == "UDP") {
        statusLabel = udpStatusLabel;
    } else if (connectionType == "P2P") {
        statusLabel = p2pStatusLabel;
    }
    
    if (statusLabel) {
        QString statusText;
        QString styleSheet;
        
        if (isConnected) {
            statusText = "Bağlı ✓";
            styleSheet = "QLabel { padding: 4px; border: 1px solid #4CAF50; border-radius: 3px; background-color: #E8F5E8; color: #2E7D32; font-weight: bold; }";
        } else {
            statusText = "Bağlı Değil ✗";
            styleSheet = "QLabel { padding: 4px; border: 1px solid #F44336; border-radius: 3px; background-color: #FFEBEE; color: #C62828; font-weight: bold; }";
        }
        
        if (!details.isEmpty()) {
            statusText += QString(" (%1)").arg(details);
        }
        
        statusLabel->setText(statusText);
        statusLabel->setStyleSheet(styleSheet);
        statusLabel->setToolTip(details);
    }
}

/**
 * @brief Şu anki konumu bulma slot'u
 */
void MainWindow::onFindMyLocation()
{
    if (!positionSource) {
        QMessageBox::warning(this, "Hata", "Konum servisi kullanılamıyor!");
        logTextEdit->append("<b>[KONUM]</b> Konum servisi kullanılamıyor");
        return;
    }
    
    findLocationButton->setEnabled(false);
    findLocationButton->setText("📍 Konum Alınıyor...");
    currentLocationLabel->setText("Mevcut Konum: Konum belirleniyor...");
    currentLocationLabel->setStyleSheet("QLabel { background-color: #FFF3E0; padding: 5px; border: 1px solid #FF9800; border-radius: 3px; }");
    
    logTextEdit->append("<b>[KONUM]</b> GPS konumu alınıyor...");
    
    // Tek seferlik konum talebi
    positionSource->requestUpdate(10000); // 10 saniye timeout
}

/**
 * @brief Konum güncellendiğinde çağrılan slot
 */
void MainWindow::onPositionUpdated(const QGeoPositionInfo &info)
{
    if (!info.isValid()) {
        onPositionError(QGeoPositionInfoSource::UnknownSourceError);
        return;
    }
    
    QGeoCoordinate coord = info.coordinate();
    currentLatitude = coord.latitude();
    currentLongitude = coord.longitude();
    hasCurrentLocation = true;
    
    // UI güncelle
    findLocationButton->setEnabled(true);
    findLocationButton->setText("📍 Şu Anki Konumumu Bul");
    
    QString locationText = QString("Mevcut Konum: %1, %2 (GPS)")
                          .arg(currentLatitude, 0, 'f', 6)
                          .arg(currentLongitude, 0, 'f', 6);
    currentLocationLabel->setText(locationText);
    currentLocationLabel->setStyleSheet("QLabel { background-color: #E8F5E8; padding: 5px; border: 1px solid #4CAF50; border-radius: 3px; }");
    
    // Haritada mevcut konumu göster (farklı şekilde)
    if (mapWidget) {
        QMetaObject::invokeMethod(mapWidget, "setCurrentLocation",
                                Q_ARG(double, currentLatitude),
                                Q_ARG(double, currentLongitude));
    }
    
    logTextEdit->append(QString("<b>[KONUM]</b> GPS konumu bulundu: %1, %2")
                       .arg(currentLatitude, 0, 'f', 6)
                       .arg(currentLongitude, 0, 'f', 6));
}

/**
 * @brief Konum hatası durumunda çağrılan slot
 */
void MainWindow::onPositionError(QGeoPositionInfoSource::Error error)
{
    findLocationButton->setEnabled(true);
    findLocationButton->setText("📍 Şu Anki Konumumu Bul");
    
    QString errorText;
    switch (error) {
        case QGeoPositionInfoSource::AccessError:
            errorText = "Konum erişim izni yok";
            break;
        case QGeoPositionInfoSource::ClosedError:
            errorText = "Konum servisi kapalı";
            break;
        case QGeoPositionInfoSource::UnknownSourceError:
        default:
            errorText = "Konum belirlenemedi";
            break;
    }
    
    currentLocationLabel->setText("Mevcut Konum: " + errorText);
    currentLocationLabel->setStyleSheet("QLabel { background-color: #FFEBEE; padding: 5px; border: 1px solid #F44336; border-radius: 3px; }");
    
    logTextEdit->append("<b>[KONUM]</b> GPS hatası: " + errorText);
}
