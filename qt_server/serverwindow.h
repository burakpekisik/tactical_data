#ifndef SERVERWINDOW_H
#define SERVERWINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QSpinBox>
#include <QTextEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QTimer>
#include <QTcpServer>
#include <QUdpSocket>
#include <QNetworkInterface>
#include <QTableWidget>
#include <QStackedWidget>
#include <QHeaderView>

class ServerMapWidget;

class ServerWindow : public QMainWindow
{
    Q_OBJECT

public:
    ServerWindow(QWidget *parent = nullptr);
    ~ServerWindow();

private slots:
    void onTcpServerToggle(bool enabled);
    void onUdpServerToggle(bool enabled);
    void onP2pServerToggle(bool enabled);
    void onServerStatusUpdate();
    void onClientDataReceived(double latitude, double longitude, const QString &dataType, const QString &message);
    void onServerTypeChanged(int index);
    void onInfoViewChanged(int index);

private:
    void setupUI();
    void setupMapPanel();
    void setupControlPanel();
    void setupServerPanel();
    void setupClientListPanel();
    void setupQueuePanel();
    void setupNotificationPanel();
    void updateServerStatus();
    void addNotification(const QString &message);
    void addClientToList(const QString &clientId, const QString &address, const QString &connectionType);
    void removeClientFromList(const QString &clientId);
    void addToQueue(const QString &message);
    void updateServerControls();
    
    // UI Components
    QWidget *centralWidget;
    QSplitter *mainSplitter;
    
    // Map Panel
    QWidget *mapPanel;
    ServerMapWidget *mapWidget;
    QLabel *serverStatusLabel;
    
    // Control Panel
    QWidget *controlPanel;
    QGroupBox *serverGroup;
    QGroupBox *infoGroup;
    QGroupBox *notificationGroup;
    
    // Server Controls
    QComboBox *serverTypeCombo;
    QStackedWidget *serverStackedWidget;
    
    // TCP Server Controls
    QWidget *tcpServerWidget;
    QCheckBox *tcpServerCheck;
    QSpinBox *tcpPortSpin;
    QLabel *tcpStatusLabel;
    
    // UDP Server Controls  
    QWidget *udpServerWidget;
    QCheckBox *udpServerCheck;
    QSpinBox *udpPortSpin;
    QLabel *udpStatusLabel;
    
    // P2P Server Controls
    QWidget *p2pServerWidget;
    QCheckBox *p2pServerCheck;
    QSpinBox *p2pPortSpin;
    QLabel *p2pStatusLabel;
    
    QPushButton *startAllButton;
    QPushButton *stopAllButton;
    QLabel *clientCountLabel;
    
    // Info Panel (Client List / Queue)
    QComboBox *infoViewCombo;
    QStackedWidget *infoStackedWidget;
    
    // Client List
    QWidget *clientListWidget;
    QTableWidget *clientListTable;
    
    // Queue List
    QWidget *queueWidget;
    QTableWidget *queueTable;
    
    // Notifications
    QTextEdit *notificationTextEdit;
    QPushButton *clearNotificationsButton;
    
    // Server Status
    bool tcpServerRunning;
    bool udpServerRunning;
    bool p2pServerRunning;
    int connectedClients;
    
    QTimer *statusUpdateTimer;
    QTcpServer *tcpServer;
    QUdpSocket *udpSocket;
};

#endif // SERVERWINDOW_H
