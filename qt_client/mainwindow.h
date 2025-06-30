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
#include "mapwidget.h"
#include "client_wrapper.h"

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
    void onSendData();
    void onConnectToServer();
    void onDisconnectFromServer();
    
    // Client wrapper slots
    void onConnectionStatusChanged(ClientWrapper::ConnectionStatus status, const QString& message);
    void onDataSendResult(ClientWrapper::SendResult result, const QString& message);
    void onDataReceived(const QString& data);
    void onLogMessage(const QString& message);
    void onReportsReceived(const QJsonArray& reports, int privilege); // <-- RAPOR SLOTU

private:
    void setupUI();
    void setupMapPanel();
    void setupControlPanel();
    void setupConnectionPanel();
    void setupDataPanel();
    void setupLogPanel();

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
    
    // Client wrapper
    ClientWrapper *clientWrapper;
    
    // Seçili nokta
    double selectedLatitude;
    double selectedLongitude;
    bool pointSelected;
    
    // Yardımcı fonksiyonlar
    void updateUIState();
    void showStatusMessage(const QString& message, int timeout = 5000);

    QPushButton *toggleMarkersButton;

    enum Mode {
        SendMode,
        ReplyMode
    };
    Mode currentMode = SendMode;
    QPushButton *modeSwitchButton; // Admin için mod değiştirici buton
    int userPrivilege = 0;
};

#endif // MAINWINDOW_H
