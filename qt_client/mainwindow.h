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
#include "mapwidget.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onMapClicked(double latitude, double longitude);
    void onSendData();
    void onConnectToServer();
    void onDisconnectFromServer();

private:
    void setupUI();
    void setupMapPanel();
    void setupControlPanel();
    void setupConnectionPanel();
    void setupDataPanel();
    void setupLogPanel();
    void updateConnectionStatus();

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
    
    // Log
    QTextEdit *logTextEdit;
    
    // Seçili nokta
    double selectedLatitude;
    double selectedLongitude;
    bool pointSelected;
    
    // Bağlantı durumu
    bool connected;
};

#endif // MAINWINDOW_H
