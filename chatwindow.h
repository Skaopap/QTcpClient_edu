#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <QtWidgets>
#include <QtNetwork>
#include <QtWidgets>

#include "ui_ChatWindow.h"

#include "rsa.h"

#include <iostream>
#include <string>

class ChatWindow : public QWidget, private Ui::ChatWindow
{
    Q_OBJECT

    public:
        ChatWindow();

    private slots:
        void on_boutonConnexion_clicked();
        void on_boutonEnvoyer_clicked();
        void on_message_returnPressed();
        void donneesRecues();
        void connecte();
        void deconnecte();
        void erreurSocket(QAbstractSocket::SocketError erreur);

        void ForwardPseudoAndPK();

        void TryConnectionTo();

        void activatedSafeSend(QString);

        void SendCrypted();

        void changePubKey();

        void changePrivKey();



    private:
        QTcpSocket *socket; // Représente le serveur
        quint16 tailleMessage;

        QMap<QString, QString> mapPseudoToPubK;
        std::pair<bool, QString> isWaitingForPK;

        QString PubKey;
        QString PrivKey;
};

#endif // CHATWINDOW_H
