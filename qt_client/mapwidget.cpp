#include "mapwidget.h"
#include <QQmlContext>
#include <QQmlEngine>
#include <QQuickItem>
#include <QDebug>

MapWidget::MapWidget(QWidget *parent)
    : QWidget(parent)
    , qmlWidget(nullptr)
    , layout(nullptr)
{
    setupQmlMap();
}

void MapWidget::setupQmlMap()
{
    layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    
    qmlWidget = new QQuickWidget(this);
    qmlWidget->setResizeMode(QQuickWidget::SizeRootObjectToView);
    
    // QML context'ine C++ nesnesini kaydet
    qmlWidget->rootContext()->setContextProperty("mapWidget", this);
    
    // QML dosyasını yükle
    qmlWidget->setSource(QUrl::fromLocalFile("map.qml"));
    
    if (qmlWidget->status() == QQuickWidget::Error) {
        qDebug() << "QML yükleme hatası:" << qmlWidget->errors();
    }
    
    layout->addWidget(qmlWidget);
    
    // QML'den gelen sinyalleri bağla
    QQuickItem *rootObject = qmlWidget->rootObject();
    if (rootObject) {
        connect(rootObject, SIGNAL(mapClicked(double, double)),
                this, SLOT(onQmlPointClicked(double, double)));
    }
}

void MapWidget::onQmlPointClicked(double latitude, double longitude)
{
    qDebug() << "Harita tıklandı:" << latitude << longitude;
    emit pointClicked(latitude, longitude);
}
