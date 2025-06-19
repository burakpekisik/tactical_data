#include <QApplication>
#include <QQmlApplicationEngine>
#include <QQuickView>
#include <QtQuickControls2>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Qt Quick Controls 2 stil ayarları
    QQuickStyle::setStyle("Material");
    
    MainWindow window;
    window.show();
    
    return app.exec();
}
