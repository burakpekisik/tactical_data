#include "servermapwidget.h"
#include <QUrl>
#include <QQmlContext>
#include <QQuickItem>

ServerMapWidget::ServerMapWidget(QWidget *parent)
    : QWidget(parent)
    , qmlWidget(nullptr)
{
    setupQmlWidget();
}

void ServerMapWidget::setupQmlWidget()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    
    qmlWidget = new QQuickWidget(this);
    qmlWidget->setSource(QUrl::fromLocalFile("servermap.qml"));
    qmlWidget->setResizeMode(QQuickWidget::SizeRootObjectToView);
    
    layout->addWidget(qmlWidget);
    
    // QML context'e C++ nesnesini expose et
    QQmlContext *context = qmlWidget->rootContext();
    context->setContextProperty("serverMapWidget", this);
}

void ServerMapWidget::addMarker(double latitude, double longitude, const QString &dataType, const QString &message)
{
    // QML'e marker ekleme sinyali gönder
    emit markerAdded(latitude, longitude, dataType, message);
    
    // QML metodunu çağır - QQuickItem'ı QObject*'e static cast et
    if (qmlWidget && qmlWidget->rootObject()) {
        QObject *rootObj = static_cast<QObject*>(qmlWidget->rootObject());
        QMetaObject::invokeMethod(rootObj, "addServerMarker",
                                Qt::QueuedConnection,
                                Q_ARG(QVariant, latitude),
                                Q_ARG(QVariant, longitude),
                                Q_ARG(QVariant, dataType),
                                Q_ARG(QVariant, message));
    }
}

void ServerMapWidget::clearMarkers()
{
    // QML metodunu çağır - QQuickItem'ı QObject*'e static cast et
    if (qmlWidget && qmlWidget->rootObject()) {
        QObject *rootObj = static_cast<QObject*>(qmlWidget->rootObject());
        QMetaObject::invokeMethod(rootObj, "clearAllMarkers",
                                Qt::QueuedConnection);
    }
}
