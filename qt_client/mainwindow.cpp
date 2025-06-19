#include "mainwindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QDateTime>

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

MainWindow::~MainWindow()
{
}

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

void MainWindow::onDisconnectFromServer()
{
    connected = false;
    updateConnectionStatus();
    
    logTextEdit->append(QString("Sunucu bağlantısı kesildi - %1")
                       .arg(QDateTime::currentDateTime().toString()));
    
    sendButton->setEnabled(false);
}

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
