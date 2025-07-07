#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QGroupBox>
#include <QSplitter>
#include <QCheckBox>
#include <QProgressBar>
#include <QTimer>
#include <QTabWidget>
#include <QGeoPositionInfoSource>
#include <QGeoPositionInfo>
#include <QIcon>
#include <QGeoCoordinate>
#include <QJsonArray>
#include <QVBoxLayout>
#include <QEvent>
#include <QMouseEvent>
#include "mapwidget.h"
#include "client_wrapper.h"
#include "notification_dialog.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    ClientWrapper* getClientWrapper() { return clientWrapper; }

private slots:
    void onMapClicked(double latitude, double longitude);
    void onMarkerClicked(int id, double latitude, double longitude);
    void onCurrentLocationMarkerClicked(double latitude, double longitude);
    void onSendData();
    void onConnectToServer();
    void onDisconnectFromServer();
    
    // Client wrapper slots
    void onConnectionStatusChanged(ClientWrapper::ConnectionStatus status, const QString& message);
    void onDataSendResult(ClientWrapper::SendResult result, const QString& message);
    void onDataReceived(const QString& data);
    void onLogMessage(const QString& message);
    void onReportsReceived(const QJsonArray& reports, int privilege); // <-- RAPOR SLOTU
    void onAdminReplyToReport();
    void onQueryMyReplies();
    void onListenForNotifications();
    void onTestConnections();
    void onAdminNotificationReceived(const QString& notification);
    void onReplyQueryResultReceived(const QJsonArray& replies);
    void onNewReportReplyReceived(int reportId, const QString& message);
    void onWatchReportReplies();
    void onConnectionTypeChanged(ClientWrapper::ConnectionType type);
    void onFallbackStatusChanged(const QString& status);
    void onFallbackTestResult(const QString& connectionType, bool success, const QString& message);
    void onPeriodicConnectionCheck(); // Periyodik bağlantı kontrolü
    
    // Konum güncellemesi slots
    void startPeriodicLocationUpdates();
    void stopPeriodicLocationUpdates();
    void onPeriodicLocationUpdate();
    
    // Admin bildirim dinleyicisi otomatik kontrol slots
    void onAutoAdminNotificationCheck();
    void startAutoAdminNotificationListener();
    void stopAutoAdminNotificationListener();
    
    // Bildirim dialog slots
    void showNotificationDialog(const QString& notification);
    void onNotificationZoomToLocation(double latitude, double longitude);
    void onNotificationReplyToReport(int reportId, const QString& initialMessage);
    void onNotificationDialogClosed();
    
    // Konum servisleri slots
    void onFindMyLocation();
    void onPositionUpdated(const QGeoPositionInfo &info);
    void onPositionError(QGeoPositionInfoSource::Error error);

private:
    void setupUI();
    void setupMapPanel();
    void setupControlPanel();
    void setupConnectionPanel();
    void setupDataPanel();
    void setupLogPanel();
    void setupAdminPanel();      // --- Yeni admin panel ---
    void setupFallbackPanel();   // --- Yeni fallback panel ---
    void setupFilterPanel();     // --- Filtreleme paneli ---
    void setupPanelToggles(); // Panel toggle butonlarını kurar

    // Event handling
    bool eventFilter(QObject *obj, QEvent *event) override;
    void togglePanel(QGroupBox* groupBox); // Panel açma/kapama

    // UI bileşenleri
    QWidget *centralWidget;
    QSplitter *mainSplitter;
    
    // Harita paneli
    QWidget *mapPanel;
    MapWidget *mapWidget;
    QLabel *coordinatesLabel;
    
    // Kontrol paneli
    QWidget *controlPanel;
    QGroupBox *connectionGroup;
    QGroupBox *dataGroup;
    QGroupBox *logGroup;
    QGroupBox *adminGroup;      // --- Yeni admin grup ---
    QGroupBox *fallbackGroup;   // --- Yeni fallback grup ---
    QGroupBox *filterGroup;     // --- Filtreleme grubu ---
    
    // Bağlantı kontrolleri
    QLineEdit *serverAddressEdit;
    QSpinBox *serverPortSpin;
    QPushButton *connectButton;
    QPushButton *disconnectButton;
    QLabel *connectionStatusLabel;
    
    // Veri kontrolleri
    QComboBox *dataTypeCombo;
    QLineEdit *messageEdit;
    QPushButton *sendButton;
    QLabel *selectedPointLabel;
    QCheckBox *encryptionCheckBox;
    QProgressBar *progressBar;
    
    // Log
    QTextEdit *logTextEdit;
    
    // --- Admin kontrolleri ---
    QPushButton *adminReplyButton;
    QPushButton *queryRepliesButton;
    QPushButton *listenNotificationsButton;
    QPushButton *watchReplyButton;
    QLineEdit *replyMessageEdit;
    QSpinBox *reportIdSpin;
    QTextEdit *adminLogEdit;
    
    // --- Fallback kontrolleri ---
    QPushButton *testConnectionsButton;
    QLabel *fallbackStatusLabel;
    QTextEdit *fallbackLogEdit;
    
    // Periyodik bağlantı kontrolü
    QTimer *connectionCheckTimer;
    QLabel *tcpStatusLabel;
    QLabel *udpStatusLabel;
    QLabel *p2pStatusLabel;
    QCheckBox *periodicCheckBox;
    
    // Periyodik kontrol durumu
    bool autoCheckEnabled = true;  // Default olarak açık
    
    // Admin bildirim dinleyicisi otomatik çalışma kontrolü
    QTimer *adminNotificationTimer;
    bool isAdminNotificationActive = false;
    int adminNotificationRetryCount = 0;
    static const int MAX_ADMIN_NOTIFICATION_RETRY = 5;
    
    // Konum servisleri
    QGeoPositionInfoSource *positionSource;
    QPushButton *findLocationButton;
    QLabel *currentLocationLabel;
    bool hasCurrentLocation = false;
    double currentLatitude = 0.0;
    double currentLongitude = 0.0;
    QTimer *locationUpdateTimer;
    bool isManualLocationRequest = false;
    
    // Client wrapper
    ClientWrapper *clientWrapper;
    
    // Seçili nokta
    double selectedLatitude;
    double selectedLongitude;
    bool pointSelected;
    
    // Yardımcı fonksiyonlar
    void updateUIState();
    void showStatusMessage(const QString& message, int timeout = 5000);
    void updateConnectionStatus(const QString& connectionType, bool isConnected, const QString& details = "");

    QPushButton *toggleMarkersButton;
    
    // Marker filtreleme kontrolleri
    QComboBox *dataTypeFilterCombo;
    QComboBox *replyStatusFilterCombo;
    QComboBox *timeFilterCombo;
    QPushButton *applyFiltersButton;
    QPushButton *clearFiltersButton;
    QLabel *filterStatusLabel;

    enum Mode {
        SendMode,
        ReplyMode
    };
    Mode currentMode = SendMode;
    QPushButton *modeSwitchButton; // Admin için mod değiştirici buton
    int userPrivilege = 0;
    bool initialReplyQueryDone = false; // İlk reply query yapıldı mı?
    QJsonArray cachedReplies; // Cached reply verilerini saklamak için

    // Bildirim dialog'u
    NotificationDialog *currentNotificationDialog = nullptr;

    // Dialog fonksiyonları
    void showAdminReplyDialog(int id, double latitude, double longitude);
    void showMarkerRepliesDialog(int id, double latitude, double longitude);
    void displayRepliesForMarker(int id, QVBoxLayout* repliesLayout);
    
    // Filtreleme fonksiyonları
    void applyMarkerFilters();
    void clearMarkerFilters();
    void updateFilterStatus();
    bool isMarkerVisible(const QJsonObject& marker);
};

#endif // MAINWINDOW_H
