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
        // Some Button managment
        void on_boutonConnexion_clicked();
        void on_boutonEnvoyer_clicked();
        void on_message_returnPressed();

        // Call when server write data on the socket
        void donneesRecues();

        // Slot when connected or deconnected from the server
        void connecte();
        void deconnecte();

        // Error message
        void errorSocket(QAbstractSocket::SocketError erreur);

        // Send pseudo and public key to server
        void ForwardPseudoAndPK();

        // Get the public key of someone on the server
        void TryConnectionTo();

        // Slot to manage send button
        void activatedSafeSend(QString);

        // Send crypted message to
        void SendCrypted();

        void changePubKey();

        void changePrivKey();



    private:
        QTcpSocket *socket;
        quint16 tailleMessage;

        QMap<QString, QString> mapPseudoToPubK; // map to store pseudo and PubKey
        std::pair<bool, QString> isWaitingForPK;

        QString PubKey;
        QString PrivKey;
};

#endif // CHATWINDOW_H
