#include <QApplication>
#include "chatwindow.h"
#include "rsa.h"

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    ChatWindow fenetre;
    fenetre.show();

    return app.exec();
}
