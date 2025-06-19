#include <QApplication>
#include "serverwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Uygulama bilgileri
    app.setApplicationName("Tactical Map Server");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("Tactical Systems");
    
    ServerWindow window;
    window.show();
    
    return app.exec();
}
