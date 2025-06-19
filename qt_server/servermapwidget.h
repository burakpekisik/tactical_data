#ifndef SERVERMAPWIDGET_H
#define SERVERMAPWIDGET_H

#include <QWidget>
#include <QQuickWidget>
#include <QVBoxLayout>

class ServerMapWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ServerMapWidget(QWidget *parent = nullptr);
    
    void addMarker(double latitude, double longitude, const QString &dataType, const QString &message);
    void clearMarkers();

signals:
    void markerAdded(double latitude, double longitude, const QString &dataType, const QString &message);

private:
    QQuickWidget *qmlWidget;
    void setupQmlWidget();
};

#endif // SERVERMAPWIDGET_H
