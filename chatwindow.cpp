#include "chatwindow.h"
#include "ui_chatwindow.h"

using namespace std;

ChatWindow::ChatWindow()
{
    setupUi(this);

    // INIT KEYS
    PubKey = "";
    PrivKey= "";
    rsa::createRsaKey(PubKey, PrivKey);

    // init class values
    isWaitingForPK  = std::make_pair(false, "");
    tailleMessage   = 0;

    // UI connection
    connect(pbSendPseudo,       SIGNAL(clicked()), this, SLOT(ForwardPseudoAndPK()));
    connect(pbChangePubKey,     SIGNAL(clicked()), this, SLOT(changePubKey()));
    connect(pbChangePrivKey,    SIGNAL(clicked()), this, SLOT(changePrivKey()));
    connect(pbSendSecured,      SIGNAL(clicked()), this, SLOT(SendCrypted()));
    connect(pbSend,             SIGNAL(clicked()), this, SLOT(on_boutonEnvoyer_clicked()));
    connect(pbTryConnection,    SIGNAL(clicked()), this, SLOT(TryConnectionTo()));

    connect(cbClientsSecured,   SIGNAL(currentTextChanged(QString)), this , SLOT(activatedSafeSend(QString)));

    // Socket connection
    socket = new QTcpSocket(this);
    connect(socket, SIGNAL(readyRead()),                            this, SLOT(donneesRecues()));
    connect(socket, SIGNAL(connected()),                            this, SLOT(connecte()));
    connect(socket, SIGNAL(disconnected()),                         this, SLOT(deconnecte()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),    this, SLOT(erreurSocket(QAbstractSocket::SocketError)));
}

// Tentative de connexion au serveur
void ChatWindow::on_boutonConnexion_clicked()
{
    // On annonce sur la fenêtre qu'on est en train de se connecter
    listeMessages->append(tr("<em>Tentative de connexion en cours...</em>"));
    boutonConnexion->setEnabled(false);

    socket->abort(); // On désactive les connexions précédentes s'il y en a
    socket->connectToHost(serveurIP->text(), serveurPort->value()); // On se connecte au serveur demandé
}

// Envoi d'un message au serveur
void ChatWindow::on_boutonEnvoyer_clicked()
{
    QByteArray paquet;
    QDataStream out(&paquet, QIODevice::WriteOnly);

    // Prepare the paquet
    QString messageAEnvoyer = tr("<strong>") + pseudo->text() +tr("</strong> : ") + message->text();

    out << (quint16) 0;
    out << messageAEnvoyer;
    out.device()->seek(0);
    out << (quint16) (paquet.size() - sizeof(quint16));

    socket->write(paquet); // send paquet

    message->clear(); // empty msg zone
    message->setFocus(); // set cursor inside
}

// Appuyer sur la touche Entrée a le même effet que cliquer sur le bouton "Envoyer"
void ChatWindow::on_message_returnPressed()
{
    on_boutonEnvoyer_clicked();
}

// On a reçu un paquet (ou un sous-paquet)
void ChatWindow::donneesRecues()
{
    /* Même principe que lorsque le serveur reçoit un paquet :
    On essaie de récupérer la taille du message
    Une fois qu'on l'a, on attend d'avoir reçu le message entier (en se basant sur la taille annoncée tailleMessage)
    */
    QDataStream in(socket);

    if (tailleMessage == 0)
    {
        if (socket->bytesAvailable() < (int)sizeof(quint16))
             return;

        in >> tailleMessage;
    }

    if (socket->bytesAvailable() < tailleMessage)
        return;


    // Si on arrive jusqu'à cette ligne, on peut récupérer le message entier
    QString messageRecu;
    in >> messageRecu;

    // APK for answer public key
    if(isWaitingForPK.first && messageRecu.indexOf("APK") == 0)
    {
        if(messageRecu.size() == 3)
        {
            tePrivate->append("<em> Error : No pseudo is matching for " + isWaitingForPK.second + "</em>");
        }
        else
        {
            mapPseudoToPubK[isWaitingForPK.second] = messageRecu.mid(3);
            tePrivate->append("<em> Secured Connection established with " + isWaitingForPK.second + "</em>");
            //tePrivate->append("pubkey de " + isWaitingForPK.second + " : " + mapPseudoToPubK[isWaitingForPK.second]);
            cbClientsSecured->addItem(isWaitingForPK.second);
            //cbClientsSecured->setCurrentIndex(cbClientsSecured->l)
        }

        isWaitingForPK.first = false;
    }
    else if (messageRecu.indexOf("CRYPTED:") == 0 )
    {
        QString msgDecrypt = rsa::rsa_pri_decrypt_base64 (messageRecu.mid(8), PrivKey);
        tePrivate->append(msgDecrypt);
    }
    else
    {
        // Display msg on chat
        listeMessages->append(messageRecu);
    }

    // reset size msg
    tailleMessage = 0;
}

// Ce slot est appelé lorsque la connexion au serveur a réussi
void ChatWindow::connecte()
{
    listeMessages->append(tr("<em>Connexion ok !</em>"));
    tabWidget->setEnabled(true);
    message->setEnabled(true);
    boutonConnexion->setEnabled(true);
}

void ChatWindow::deconnecte()
{
    listeMessages->append(tr("<em>Disconnected from the server</em>"));
    pbTryConnection->setEnabled(false);
    pbSend->setEnabled(false);
    pbSendSecured->setEnabled(false);
    tabWidget->setEnabled(false);
}

void ChatWindow::erreurSocket(QAbstractSocket::SocketError erreur)
{
    switch(erreur) // display error
    {
        case QAbstractSocket::HostNotFoundError:
            listeMessages->append(tr("<em>ERROR : Server not found. Check Ip and Port.</em>"));
            break;
        case QAbstractSocket::ConnectionRefusedError:
            listeMessages->append(tr("<em>ERROR : Server has refused the connexion. Check if \"server\" is running. Check Ip and Port.</em>"));
            break;
        case QAbstractSocket::RemoteHostClosedError:
            listeMessages->append(tr("<em>ERROR : Server stopped the connexion.</em>"));
            break;
        default:
            listeMessages->append(tr("<em>ERROR : ") + socket->errorString() + tr("</em>"));
    }

    boutonConnexion->setEnabled(true);
}

void ChatWindow::ForwardPseudoAndPK()
{
    QByteArray paquet;
    QDataStream out(&paquet, QIODevice::WriteOnly);

    // On prépare le paquet à envoyer
    QString messageAEnvoyer =tr("P:") + pseudo->text() + tr(" PubKey") + PubKey;

    out << (quint16) 0;
    out << messageAEnvoyer;
    out.device()->seek(0);
    out << (quint16) (paquet.size() - sizeof(quint16));

    socket->write(paquet); // send paquet

    // disable some ui part
    pseudo->setEnabled(false);
    pbSendPseudo->setEnabled(false);
    pbTryConnection->setEnabled(true);
    pbSend->setEnabled(true);

    message->clear();
    message->setFocus();
}

void ChatWindow::TryConnectionTo()
{
    QByteArray paquet;
    QDataStream out(&paquet, QIODevice::WriteOnly);

    QString messageAEnvoyer =tr("ConnectTo") + lePseudo->text();
    isWaitingForPK = std::make_pair(true, lePseudo->text());

    out << (quint16) 0;
    out << messageAEnvoyer;
    out.device()->seek(0);
    out << (quint16) (paquet.size() - sizeof(quint16));

    socket->write(paquet);

    tePrivate->append(QString("<em>Waiting for connection..</em>"));
}

void ChatWindow::activatedSafeSend(QString str )
{
    if( str != "")
        pbSendSecured->setEnabled(true);
    else
        pbSendSecured->setEnabled(false);
}

void ChatWindow::SendCrypted()
{
    QByteArray paquet;
    QDataStream out(&paquet, QIODevice::WriteOnly);

    // Prepare msg and encrypt with pub key from the desired client
    QString msg = "<strong>" + pseudo->text() + ": </strong>" + leSafeMsg->text();
    tePrivate->append(msg);
    msg = rsa::rsa_pub_encrypt_base64(msg, mapPseudoToPubK[cbClientsSecured->currentText()]);

    QString messageAEnvoyer =tr("Pseudo:") + cbClientsSecured->currentText() + " MSG:" + msg ;

    out << (quint16) 0;
    out << messageAEnvoyer;
    out.device()->seek(0);
    out << (quint16) (paquet.size() - sizeof(quint16));

    leSafeMsg->clear();

    socket->write(paquet); // send paquet
}

void ChatWindow::changePubKey()
{
    PubKey = tePubKey->toPlainText();
    tePubKey->append("<em>PubKey Changed !</em>");
}

void ChatWindow::changePrivKey()
{
    PrivKey = tePrivKey->toPlainText();
    tePrivKey->append("<em>PrivKey Changed !</em>");
}
