#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <QtWidgets>
#include <QtNetwork>
#include <QtWidgets>

#include "ui_ChatWindow.h"

#include "rsa.h"

#include <iostream>
#include <string>

//!  Chat ui class
/*!
  Manage all ui interaction and data sending to the server.
*/
class ChatWindow : public QWidget, private Ui::ChatWindow
{
Q_OBJECT

public:

/*!
 * \brief Constructor
*/
ChatWindow();

private slots:

/*!
 * \brief Connection event button
*/
void on_boutonConnexion_clicked();

/*!
 * \brief Send event button general
*/
void on_boutonEnvoyer_clicked();

/*!
 * \brief Send event button general, second way
*/
void on_message_returnPressed();

/*!
 * \brief Called when the client is receivintg data from the server
 *          Display the message in the right chat
*/
void DataReceived();

/*!
 * \brief Called when the client is connected to the server
*/
void connecte();

/*!
 * \brief Called when the client is disconnected to the server
*/
void deconnecte();

/*!
 * \brief Get and dispplay the error
 * \param erreur socket error
*/
void errorSocket(QAbstractSocket::SocketError erreur);

/*!
 * \brief Send pseudo and private key to the connected server
*/
void ForwardPseudoAndPK();

/*!
 * \brief Get the public key of someone on the server
*/
void TryConnectionTo();

/*!
 * \brief Manage send button
 * \param str pseudo of selected client
*/
void activatedSafeSend(QString str);

/*!
 * \brief Send crypted message to the selected client
*/
void SendCrypted();

/*!
 * \brief Change the public key and clear the text field
*/
void changePubKey();

/*!
 * \brief Change the private key and clear the text field
*/
void changePrivKey();



private:

QTcpSocket *socket; /*!< Pointer to the TCP socket */

quint16 tailleMessage; /*!< Current size of the receiving message */

QMap<QString, QString> mapPseudoToPubK; /*!< QMap to link clients pseudo and their public keys */

std::pair<bool, QString> isWaitingForPK; /*!< Pair to manage the reception of the public key */

QString PubKey; /*!< Public Key */

QString PrivKey; /*!< Private Key */
};

#endif // CHATWINDOW_H
