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
#include <QApplication>
#include <QMessageBox>
#include <QDateTime>

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
    , connected(false)
{
    setupUI();
    setWindowTitle("Tactical Data Client - Harita Arayüzü");
    setMinimumSize(1200, 800);
    resize(1400, 900);
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
    
    updateConnectionStatus();
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
    
    mapLayout->addWidget(mapWidget, 1); // Haritaya genişleme faktörü ekle
    mapLayout->addWidget(coordinatesLabel);
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
    
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::onSendData);
    
    dataLayout->addWidget(selectedPointLabel);
    dataLayout->addLayout(typeLayout);
    dataLayout->addLayout(messageLayout);
    dataLayout->addWidget(sendButton);
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
 *          içeren paneli oluşturur. Bağlantı durumuna göre bileşenleri etkinleştirir/devre dışı bırakır.
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
    
    // Gönder butonunu etkinleştir (eğer bağlıysa)
    sendButton->setEnabled(connected && pointSelected);
    
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
    if (!connected) {
        QMessageBox::warning(this, "Uyarı", "Sunucuya bağlı değilsiniz!");
        return;
    }
    
    if (!pointSelected) {
        QMessageBox::warning(this, "Uyarı", "Önce haritadan bir nokta seçin!");
        return;
    }
    
    QString dataType = dataTypeCombo->currentText();
    QString message = messageEdit->text();
    
    // Bu noktada gerçek veri gönderimi yapılacak
    // Şimdilik sadece log'a yazıyoruz
    QString logMessage = QString("Veri gönderildi - Tip: %1, Koordinat: %2,%3, Mesaj: %4 - %5")
                        .arg(dataType)
                        .arg(selectedLatitude, 0, 'f', 6)
                        .arg(selectedLongitude, 0, 'f', 6)
                        .arg(message)
                        .arg(QDateTime::currentDateTime().toString());
    
    logTextEdit->append(logMessage);
    
    QMessageBox::information(this, "Başarılı", "Veri başarıyla gönderildi!");
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
    
    // Bu noktada gerçek bağlantı kurulacak
    // Şimdilik simüle ediyoruz
    connected = true;
    updateConnectionStatus();
    
    logTextEdit->append(QString("Sunucuya bağlanıldı: %1:%2 - %3")
                       .arg(address)
                       .arg(port)
                       .arg(QDateTime::currentDateTime().toString()));
    
    sendButton->setEnabled(connected && pointSelected);
}

/**
 * @brief Sunucu bağlantısını keser
 * @details Mevcut sunucu bağlantısını sonlandırır, bağlantı durumunu günceller
 *          ve log'a kaydeder. UI bileşenlerinin durumlarını resetler.
 * @note Bağlantı kesildikten sonra veri gönderimi devre dışı kalır
 */
void MainWindow::onDisconnectFromServer()
{
    connected = false;
    updateConnectionStatus();
    
    logTextEdit->append(QString("Sunucu bağlantısı kesildi - %1")
                       .arg(QDateTime::currentDateTime().toString()));
    
    sendButton->setEnabled(false);
}

/**
 * @brief Bağlantı durumuna göre UI bileşenlerini günceller
 * @details Bağlantı durumuna göre butonların etkin/devre dışı durumlarını,
 *          durum etiketinin rengini ve girdi alanlarının düzenlenebilirliğini ayarlar.
 * @note Bu fonksiyon bağlantı kurulduğunda ve kesildiğinde çağrılır
 * @see onConnectToServer(), onDisconnectFromServer()
 */
void MainWindow::updateConnectionStatus()
{
    if (connected) {
        connectionStatusLabel->setText("Bağlantı Durumu: Bağlı");
        connectionStatusLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
        connectButton->setEnabled(false);
        disconnectButton->setEnabled(true);
        serverAddressEdit->setEnabled(false);
        serverPortSpin->setEnabled(false);
    } else {
        connectionStatusLabel->setText("Bağlantı Durumu: Bağlı Değil");
        connectionStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        connectButton->setEnabled(true);
        disconnectButton->setEnabled(false);
        serverAddressEdit->setEnabled(true);
        serverPortSpin->setEnabled(true);
    }
}
