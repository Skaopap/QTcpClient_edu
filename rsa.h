#ifndef RSA_H
#define RSA_H

#include <QDebug>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// define rsa public key
#define BEGIN_RSA_PUBLIC_KEY    "BEGIN RSA PUBLIC KEY"
#define BEGIN_PUBLIC_KEY        "BEGIN PUBLIC KEY"
#define KEY_LENGTH 1024 // key length

class rsa
{
public:

/**
 * @brief createRsaKey generates a key pair
 * @param strPubKey public key
 * @param strPriKey private key
 * @return status
*/
static bool createRsaKey (QString& strPubKey, QString& strPriKey);

/**
 * @brief rsa_pub_encrypt public key encryption
 * @param strClearData Clear text
 * @param strPubKey private key
 * @return Encrypted data (base64 format)
*/
static QString rsa_pub_encrypt_base64 (const QString& strClearData, const QString& strPubKey);

/**
 * @brief rsa_pri_decrypt private key decryption
 * @param strDecrypt data to be decrypted (base64 format)
 * @param strPriKey private key
 * @return Clear text
*/
static QString rsa_pri_decrypt_base64 (const QString& strDecryptData, const QString& strPriKey);

 /**<test */
static void test ();

};
#endif // RSA_H
