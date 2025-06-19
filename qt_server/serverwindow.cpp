#include "serverwindow.h"
#include "servermapwidget.h"
#include <QApplication>
#include <QMessageBox>
#include <QDateTime>
#include <QHostAddress>
#include <QScrollBar>
#include <random>

ServerWindow::ServerWindow(QWidget *parent)
    : QMainWindow(parent)
    , centralWidget(nullptr)
    , mainSplitter(nullptr)
    , mapPanel(nullptr)
    , mapWidget(nullptr)
    , controlPanel(nullptr)
    , tcpServerRunning(false)
    , udpServerRunning(false)
    , p2pServerRunning(false)
    , connectedClients(0)
    , tcpServer(nullptr)
    , udpSocket(nullptr)
{
    setupUI();
    setWindowTitle("Tactical Data Server - Sunucu Yönetim Paneli");
    setMinimumSize(1200, 800);
    resize(1400, 900);
    
    // Status update timer
    statusUpdateTimer = new QTimer(this);
    connect(statusUpdateTimer, &QTimer::timeout, this, &ServerWindow::onServerStatusUpdate);
    statusUpdateTimer->start(1000); // Her saniye güncelle
    
    updateServerStatus();
    addNotification("Sunucu yönetim paneli başlatıldı");
}

ServerWindow::~ServerWindow()
{
    if (tcpServer) {
        tcpServer->close();
        delete tcpServer;
    }
    if (udpSocket) {
        udpSocket->close();
        delete udpSocket;
    }
}

void ServerWindow::setupUI()
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

void ServerWindow::setupMapPanel()
{
    mapPanel = new QWidget();
    mapPanel->setMinimumWidth(600);
    
    QVBoxLayout *mapLayout = new QVBoxLayout(mapPanel);
    
    // Harita widget'ı
    mapWidget = new ServerMapWidget(this);
    
    // Sunucu durumu
    serverStatusLabel = new QLabel("Sunucu Durumu: Hazır");
    serverStatusLabel->setStyleSheet("QLabel { background-color: #e8f4f8; padding: 5px; border: 1px solid #ccc; font-weight: bold; }");
    
    mapLayout->addWidget(mapWidget, 1); // Haritaya genişleme faktörü ekle
    mapLayout->addWidget(serverStatusLabel);
    mapLayout->setContentsMargins(5, 5, 5, 5);
}

void ServerWindow::setupControlPanel()
{
    controlPanel = new QWidget();
    controlPanel->setMaximumWidth(400);
    controlPanel->setMinimumWidth(350);
    
    QVBoxLayout *controlLayout = new QVBoxLayout(controlPanel);
    
    setupServerPanel();
    setupClientListPanel();
    setupNotificationPanel();
    
    controlLayout->addWidget(serverGroup);
    controlLayout->addWidget(infoGroup);
    controlLayout->addWidget(notificationGroup);
    controlLayout->setContentsMargins(5, 5, 5, 5);
}

void ServerWindow::setupServerPanel()
{
    serverGroup = new QGroupBox("Sunucu Kontrolleri");
    QVBoxLayout *serverLayout = new QVBoxLayout(serverGroup);
    
    // Sunucu türü seçimi
    QHBoxLayout *serverTypeLayout = new QHBoxLayout();
    serverTypeLayout->addWidget(new QLabel("Sunucu Türü:"));
    serverTypeCombo = new QComboBox();
    serverTypeCombo->addItems({"TCP Sunucusu", "UDP Sunucusu", "P2P Sunucusu"});
    connect(serverTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &ServerWindow::onServerTypeChanged);
    serverTypeLayout->addWidget(serverTypeCombo);
    
    // Stacked widget for different server controls
    serverStackedWidget = new QStackedWidget();
    
    // TCP Server Widget
    tcpServerWidget = new QWidget();
    QVBoxLayout *tcpLayout = new QVBoxLayout(tcpServerWidget);
    
    tcpServerCheck = new QCheckBox("TCP Sunucusunu Etkinleştir");
    connect(tcpServerCheck, &QCheckBox::toggled, this, &ServerWindow::onTcpServerToggle);
    
    QHBoxLayout *tcpPortLayout = new QHBoxLayout();
    tcpPortLayout->addWidget(new QLabel("Port:"));
    tcpPortSpin = new QSpinBox();
    tcpPortSpin->setRange(1024, 65535);
    tcpPortSpin->setValue(8080);
    tcpPortLayout->addWidget(tcpPortSpin);
    
    tcpStatusLabel = new QLabel("Durum: Kapalı");
    tcpStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    
    tcpLayout->addWidget(tcpServerCheck);
    tcpLayout->addLayout(tcpPortLayout);
    tcpLayout->addWidget(tcpStatusLabel);
    
    // UDP Server Widget
    udpServerWidget = new QWidget();
    QVBoxLayout *udpLayout = new QVBoxLayout(udpServerWidget);
    
    udpServerCheck = new QCheckBox("UDP Sunucusunu Etkinleştir");
    connect(udpServerCheck, &QCheckBox::toggled, this, &ServerWindow::onUdpServerToggle);
    
    QHBoxLayout *udpPortLayout = new QHBoxLayout();
    udpPortLayout->addWidget(new QLabel("Port:"));
    udpPortSpin = new QSpinBox();
    udpPortSpin->setRange(1024, 65535);
    udpPortSpin->setValue(8081);
    udpPortLayout->addWidget(udpPortSpin);
    
    udpStatusLabel = new QLabel("Durum: Kapalı");
    udpStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    
    udpLayout->addWidget(udpServerCheck);
    udpLayout->addLayout(udpPortLayout);
    udpLayout->addWidget(udpStatusLabel);
    
    // P2P Server Widget
    p2pServerWidget = new QWidget();
    QVBoxLayout *p2pLayout = new QVBoxLayout(p2pServerWidget);
    
    p2pServerCheck = new QCheckBox("P2P Sunucusunu Etkinleştir");
    connect(p2pServerCheck, &QCheckBox::toggled, this, &ServerWindow::onP2pServerToggle);
    
    QHBoxLayout *p2pPortLayout = new QHBoxLayout();
    p2pPortLayout->addWidget(new QLabel("Port:"));
    p2pPortSpin = new QSpinBox();
    p2pPortSpin->setRange(1024, 65535);
    p2pPortSpin->setValue(8082);
    p2pPortLayout->addWidget(p2pPortSpin);
    
    p2pStatusLabel = new QLabel("Durum: Kapalı");
    p2pStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    
    p2pLayout->addWidget(p2pServerCheck);
    p2pLayout->addLayout(p2pPortLayout);
    p2pLayout->addWidget(p2pStatusLabel);
    
    // Add widgets to stacked widget
    serverStackedWidget->addWidget(tcpServerWidget);
    serverStackedWidget->addWidget(udpServerWidget);
    serverStackedWidget->addWidget(p2pServerWidget);
    
    // Kontrol Butonları
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    startAllButton = new QPushButton("Tümünü Başlat");
    stopAllButton = new QPushButton("Tümünü Durdur");
    startAllButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }");
    stopAllButton->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 8px; }");
    
    buttonLayout->addWidget(startAllButton);
    buttonLayout->addWidget(stopAllButton);
    
    // Bağlı istemci sayısı
    clientCountLabel = new QLabel("Bağlı İstemciler: 0");
    clientCountLabel->setStyleSheet("QLabel { background-color: #fff3cd; padding: 5px; border: 1px solid #ffeeba; font-weight: bold; }");
    
    serverLayout->addLayout(serverTypeLayout);
    serverLayout->addWidget(serverStackedWidget);
    serverLayout->addLayout(buttonLayout);
    serverLayout->addWidget(clientCountLabel);
}

void ServerWindow::setupClientListPanel()
{
    infoGroup = new QGroupBox("İstemci Bilgileri");
    QVBoxLayout *infoLayout = new QVBoxLayout(infoGroup);
    
    // Info view selector
    QHBoxLayout *infoViewLayout = new QHBoxLayout();
    infoViewLayout->addWidget(new QLabel("Görünüm:"));
    infoViewCombo = new QComboBox();
    infoViewCombo->addItems({"İstemci Listesi", "Kuyruk Listesi"});
    connect(infoViewCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &ServerWindow::onInfoViewChanged);
    infoViewLayout->addWidget(infoViewCombo);
    
    // Stacked widget for different info views
    infoStackedWidget = new QStackedWidget();
    
    // Client List Widget
    clientListWidget = new QWidget();
    QVBoxLayout *clientLayout = new QVBoxLayout(clientListWidget);
    
    clientListTable = new QTableWidget(0, 4);
    clientListTable->setHorizontalHeaderLabels({"İstemci ID", "IP Adresi", "Bağlantı Türü", "Durum"});
    clientListTable->horizontalHeader()->setStretchLastSection(true);
    clientListTable->setAlternatingRowColors(true);
    clientListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    
    clientLayout->addWidget(clientListTable);
    
    // Queue Widget
    queueWidget = new QWidget();
    QVBoxLayout *queueLayout = new QVBoxLayout(queueWidget);
    
    queueTable = new QTableWidget(0, 3);
    queueTable->setHorizontalHeaderLabels({"Zaman", "Mesaj Türü", "İçerik"});
    queueTable->horizontalHeader()->setStretchLastSection(true);
    queueTable->setAlternatingRowColors(true);
    queueTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    
    queueLayout->addWidget(queueTable);
    
    // Add widgets to stacked widget
    infoStackedWidget->addWidget(clientListWidget);
    infoStackedWidget->addWidget(queueWidget);
    
    infoLayout->addLayout(infoViewLayout);
    infoLayout->addWidget(infoStackedWidget);
}

void ServerWindow::setupNotificationPanel()
{
    notificationGroup = new QGroupBox("Son Bildirimler");
    QVBoxLayout *notificationLayout = new QVBoxLayout(notificationGroup);
    
    notificationTextEdit = new QTextEdit();
    notificationTextEdit->setMaximumHeight(250);
    notificationTextEdit->setReadOnly(true);
    notificationTextEdit->append("Sistem başlatıldı - " + QDateTime::currentDateTime().toString());
    
    clearNotificationsButton = new QPushButton("Bildirimleri Temizle");
    clearNotificationsButton->setStyleSheet("QPushButton { background-color: #6c757d; color: white; padding: 5px; }");
    connect(clearNotificationsButton, &QPushButton::clicked, [this]() {
        notificationTextEdit->clear();
        addNotification("Bildirimler temizlendi");
    });
    
    notificationLayout->addWidget(notificationTextEdit);
    notificationLayout->addWidget(clearNotificationsButton);
}

void ServerWindow::onTcpServerToggle(bool enabled)
{
    if (enabled) {
        if (!tcpServer) {
            tcpServer = new QTcpServer(this);
        }
        
        if (tcpServer->listen(QHostAddress::Any, tcpPortSpin->value())) {
            tcpServerRunning = true;
            tcpStatusLabel->setText("Durum: Açık");
            tcpStatusLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
            tcpPortSpin->setEnabled(false);
            addNotification(QString("TCP Sunucusu başlatıldı - Port: %1").arg(tcpPortSpin->value()));
        } else {
            tcpServerCheck->setChecked(false);
            QMessageBox::warning(this, "Hata", "TCP Sunucusu başlatılamadı!");
            addNotification("TCP Sunucusu başlatılamadı");
        }
    } else {
        if (tcpServer) {
            tcpServer->close();
        }
        tcpServerRunning = false;
        tcpStatusLabel->setText("Durum: Kapalı");
        tcpStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        tcpPortSpin->setEnabled(true);
        addNotification("TCP Sunucusu durduruldu");
    }
    updateServerStatus();
}

void ServerWindow::onUdpServerToggle(bool enabled)
{
    if (enabled) {
        if (!udpSocket) {
            udpSocket = new QUdpSocket(this);
        }
        
        if (udpSocket->bind(QHostAddress::Any, udpPortSpin->value())) {
            udpServerRunning = true;
            udpStatusLabel->setText("Durum: Açık");
            udpStatusLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
            udpPortSpin->setEnabled(false);
            addNotification(QString("UDP Sunucusu başlatıldı - Port: %1").arg(udpPortSpin->value()));
        } else {
            udpServerCheck->setChecked(false);
            QMessageBox::warning(this, "Hata", "UDP Sunucusu başlatılamadı!");
            addNotification("UDP Sunucusu başlatılamadı");
        }
    } else {
        if (udpSocket) {
            udpSocket->close();
        }
        udpServerRunning = false;
        udpStatusLabel->setText("Durum: Kapalı");
        udpStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        udpPortSpin->setEnabled(true);
        addNotification("UDP Sunucusu durduruldu");
    }
    updateServerStatus();
}

void ServerWindow::onP2pServerToggle(bool enabled)
{
    // P2P sunucusu için simüle edilmiş durum
    p2pServerRunning = enabled;
    
    if (enabled) {
        p2pStatusLabel->setText("Durum: Açık");
        p2pStatusLabel->setStyleSheet("QLabel { color: green; font-weight: bold; }");
        p2pPortSpin->setEnabled(false);
        addNotification(QString("P2P Sunucusu başlatıldı - Port: %1").arg(p2pPortSpin->value()));
    } else {
        p2pStatusLabel->setText("Durum: Kapalı");
        p2pStatusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        p2pPortSpin->setEnabled(true);
        addNotification("P2P Sunucusu durduruldu");
    }
    updateServerStatus();
}

void ServerWindow::onServerStatusUpdate()
{
    // Bağlı istemci sayısını güncelle (simüle edilmiş)
    static int simulatedClients = 0;
    static bool demoDataAdded = false;
    
    if (tcpServerRunning || udpServerRunning || p2pServerRunning) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 4);
        simulatedClients = dis(gen); // 0-4 arası rastgele istemci sayısı
        
        // Demo veri ekle (sadece bir kez)
        if (!demoDataAdded) {
            // Demo istemciler ekle
            addClientToList("CLIENT_001", "192.168.1.100", "TCP");
            addClientToList("CLIENT_002", "192.168.1.101", "UDP");
            addClientToList("CLIENT_003", "192.168.1.102", "P2P");
            
            // Demo queue verileri ekle
            addToQueue("Tactical Position Update - Ankara");
            addToQueue("Enemy Contact Detected - Grid 125.456");
            addToQueue("Friendly Unit Status - Alpha Team");
            
            demoDataAdded = true;
        }
    } else {
        simulatedClients = 0;
        // Sunucular kapalıysa istemci listesini temizle
        if (demoDataAdded) {
            clientListTable->clearContents();
            clientListTable->setRowCount(0);
            demoDataAdded = false;
        }
    }
    
    connectedClients = simulatedClients;
    clientCountLabel->setText(QString("Bağlı İstemciler: %1").arg(connectedClients));
}

void ServerWindow::updateServerStatus()
{
    QString status = "Sunucu Durumu: ";
    int activeServers = 0;
    
    if (tcpServerRunning) activeServers++;
    if (udpServerRunning) activeServers++;
    if (p2pServerRunning) activeServers++;
    
    if (activeServers == 0) {
        status += "Tüm Sunucular Kapalı";
        serverStatusLabel->setStyleSheet("QLabel { background-color: #f8d7da; padding: 5px; border: 1px solid #f5c6cb; font-weight: bold; color: #721c24; }");
    } else if (activeServers == 3) {
        status += "Tüm Sunucular Aktif";
        serverStatusLabel->setStyleSheet("QLabel { background-color: #d4edda; padding: 5px; border: 1px solid #c3e6cb; font-weight: bold; color: #155724; }");
    } else {
        status += QString("%1/3 Sunucu Aktif").arg(activeServers);
        serverStatusLabel->setStyleSheet("QLabel { background-color: #fff3cd; padding: 5px; border: 1px solid #ffeeba; font-weight: bold; color: #856404; }");
    }
    
    serverStatusLabel->setText(status);
}

void ServerWindow::addNotification(const QString &message)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    notificationTextEdit->append(QString("[%1] %2").arg(timestamp, message));
    notificationTextEdit->verticalScrollBar()->setValue(notificationTextEdit->verticalScrollBar()->maximum());
}

void ServerWindow::onClientDataReceived(double latitude, double longitude, const QString &dataType, const QString &message)
{
    // İstemciden gelen veri işlemi
    addNotification(QString("Veri alındı - %1: %2, %3 - %4").arg(dataType).arg(latitude, 0, 'f', 6).arg(longitude, 0, 'f', 6).arg(message));
    
    // Haritaya işaret ekle (gelecekte implementasyonu)
    // mapWidget->addMarker(latitude, longitude, dataType, message);
}

void ServerWindow::onServerTypeChanged(int index)
{
    serverStackedWidget->setCurrentIndex(index);
}

void ServerWindow::onInfoViewChanged(int index)
{
    infoStackedWidget->setCurrentIndex(index);
}

void ServerWindow::addClientToList(const QString &clientId, const QString &address, const QString &connectionType)
{
    int row = clientListTable->rowCount();
    clientListTable->insertRow(row);
    
    clientListTable->setItem(row, 0, new QTableWidgetItem(clientId));
    clientListTable->setItem(row, 1, new QTableWidgetItem(address));
    clientListTable->setItem(row, 2, new QTableWidgetItem(connectionType));
    clientListTable->setItem(row, 3, new QTableWidgetItem("Bağlı"));
    
    // Durum rengini ayarla
    QTableWidgetItem *statusItem = clientListTable->item(row, 3);
    statusItem->setBackground(QColor(212, 237, 218)); // Açık yeşil
    
    addNotification(QString("Yeni istemci bağlandı: %1 (%2)").arg(clientId, address));
}

void ServerWindow::removeClientFromList(const QString &clientId)
{
    for (int row = 0; row < clientListTable->rowCount(); ++row) {
        if (clientListTable->item(row, 0)->text() == clientId) {
            QString address = clientListTable->item(row, 1)->text();
            clientListTable->removeRow(row);
            addNotification(QString("İstemci bağlantısı kesildi: %1 (%2)").arg(clientId, address));
            break;
        }
    }
}

void ServerWindow::addToQueue(const QString &message)
{
    int row = queueTable->rowCount();
    queueTable->insertRow(row);
    
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    queueTable->setItem(row, 0, new QTableWidgetItem(timestamp));
    queueTable->setItem(row, 1, new QTableWidgetItem("Tactical Data"));
    queueTable->setItem(row, 2, new QTableWidgetItem(message));
    
    // Scroll to bottom
    queueTable->scrollToBottom();
}
