#include "rsa.h"
/**
 * @brief createRsaKey generates a key pair
 * @param strPubKey public key
 * @param strPriKey private key
 * @return success status
*/
bool rsa::createRsaKey (QString& strPubKey, QString& strPriKey)
{
     RSA *pRsa = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
     if ( !pRsa ){
         return false;
     }
     BIO *pPriBio = BIO_new(BIO_s_mem());
     PEM_write_bio_RSAPrivateKey(pPriBio, pRsa, NULL, NULL, 0, NULL, NULL);
     BIO *pPubBio = BIO_new(BIO_s_mem());
     PEM_write_bio_RSAPublicKey(pPubBio, pRsa);
 // get the length
     size_t nPriKeyLen = BIO_pending(pPriBio);
     size_t nPubKeyLen = BIO_pending(pPubBio);
 // The key pair is read to the string
     char* pPriKey = new char[nPriKeyLen];
     char* pPubKey = new char[nPubKeyLen];
     BIO_read(pPriBio, pPriKey, nPriKeyLen);
     BIO_read(pPubBio, pPubKey, nPubKeyLen);
 // store key pair
     strPubKey = QByteArray(pPubKey, nPubKeyLen);
     strPriKey = QByteArray(pPriKey, nPriKeyLen);
 // memory release
     RSA_free(pRsa);
     BIO_free_all(pPriBio);
     BIO_free_all(pPubBio);
     delete pPriKey;
     delete pPubKey;
     return true;
}

/**
   * @brief rsa_pri_encrypt private key encryption
   * @param strClearData Clear text
   * @param strPriKey private key
   * @return Encrypted data (base64 format)
 */
QString rsa::rsa_pri_encrypt_base64 (const QString& strClearData, const QString& strPriKey)
{
    QByteArray priKeyArry = strPriKey.toUtf8();
    uchar* pPriKey = (uchar*)priKeyArry.data();
    BIO* pKeyBio = BIO_new_mem_buf(pPriKey, strPriKey.length());
    if (pKeyBio == NULL){
        return "";
    }
    RSA* pRsa = RSA_new();
    pRsa = PEM_read_bio_RSAPrivateKey(pKeyBio, &pRsa, NULL, NULL);
    if ( pRsa == NULL ){
         BIO_free_all(pKeyBio);
         return "";
    }
    int nLen = RSA_size(pRsa);
    char* pEncryptBuf = new char[nLen];
    memset(pEncryptBuf, 0, nLen);
    QByteArray clearDataArry = strClearData.toUtf8();
    int nClearDataLen = clearDataArry.length();
    uchar* pClearData = (uchar*)clearDataArry.data();
    int nSize = RSA_private_encrypt(nClearDataLen,
                                    pClearData,
                                    (uchar*)pEncryptBuf,
                                    pRsa,
                                    RSA_PKCS1_PADDING);
    QString strEncryptData = "";
    if ( nSize >= 0 ){
         QByteArray arry(pEncryptBuf, nSize);
         strEncryptData = arry.toBase64();
    }
 // free memory
    delete pEncryptBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strEncryptData;
}

/**
   * @brief rsa_pub_decrypt public key decryption
   * @param strDecrypt data to be decrypted (base64 format)
   * @param strPubKey public key
   * @return Clear text
 */
QString rsa::rsa_pub_decrypt_base64(const QString& strDecryptData, const QString& strPubKey)
{
    QByteArray pubKeyArry = strPubKey.toUtf8();
    uchar* pPubKey = (uchar*)pubKeyArry.data();
    BIO* pKeyBio = BIO_new_mem_buf(pPubKey, strPubKey.length());
    if (pKeyBio == NULL){
        return "";
    }

    RSA* pRsa = RSA_new();
    if ( strPubKey.contains(BEGIN_RSA_PUBLIC_KEY) ){
        pRsa = PEM_read_bio_RSAPublicKey(pKeyBio, &pRsa, NULL, NULL);
    }else{
        pRsa = PEM_read_bio_RSA_PUBKEY(pKeyBio, &pRsa, NULL, NULL);
    }

    if ( pRsa == NULL ){
        BIO_free_all(pKeyBio);
        return "";
    }
    int nLen = RSA_size(pRsa);
    char* pClearBuf = new char[nLen];
    memset(pClearBuf, 0, nLen);
         //decrypt
    QByteArray decryptDataArry = strDecryptData.toUtf8();
    decryptDataArry = QByteArray::fromBase64(decryptDataArry);
    int nDecryptDataLen = decryptDataArry.length();
    uchar* pDecryptData = (uchar*)decryptDataArry.data();
    int nSize = RSA_public_decrypt(nDecryptDataLen,
                                   pDecryptData,
                                   (uchar*)pClearBuf,
                                   pRsa,
                                   RSA_PKCS1_PADDING);
    QString strClearData = "";
    if ( nSize >= 0 ){
        strClearData = QByteArray(pClearBuf, nSize);
    }

         // free memory
    delete pClearBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strClearData;
}

/**
 * @brief rsa_pub_encrypt public key encryption
   * @param strClearData Clear text
   * @param strPubKey private key
   * @return Encrypted data (base64 format)
 */
QString rsa::rsa_pub_encrypt_base64 (const QString& strClearData, const QString& strPubKey)
{
    QByteArray pubKeyArry = strPubKey.toUtf8();
    uchar* pPubKey = (uchar*)pubKeyArry.data();
    BIO* pKeyBio = BIO_new_mem_buf(pPubKey, pubKeyArry.length());
    if (pKeyBio == NULL){
        return "";
    }
    RSA* pRsa = RSA_new();
    if ( strPubKey.contains(BEGIN_RSA_PUBLIC_KEY) ){
        pRsa = PEM_read_bio_RSAPublicKey(pKeyBio, &pRsa, NULL, NULL);
    }else{
        pRsa = PEM_read_bio_RSA_PUBKEY(pKeyBio, &pRsa, NULL, NULL);
    }
    if ( pRsa == NULL ){
        BIO_free_all(pKeyBio);
        return "";
    }

    int nLen = RSA_size(pRsa);
    char* pEncryptBuf = new char[nLen];
    memset(pEncryptBuf, 0, nLen);

    QByteArray clearDataArry = strClearData.toUtf8();
    int nClearDataLen = clearDataArry.length();
    uchar* pClearData = (uchar*)clearDataArry.data();
    int nSize = RSA_public_encrypt(nClearDataLen,
                                   pClearData,
                                   (uchar*)pEncryptBuf,
                                   pRsa,
                                   RSA_PKCS1_PADDING);
    QString strEncryptData = "";
    if ( nSize >= 0 ){
        QByteArray arry(pEncryptBuf, nSize);
        strEncryptData = arry.toBase64();
    }
         // free memory
    delete pEncryptBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strEncryptData;
}

/**
   * @brief rsa_pri_decrypt private key decryption
   * @param strDecrypt data to be decrypted (base64 format)
   * @param strPriKey private key
   * @return Clear text
 */
QString rsa::rsa_pri_decrypt_base64(const QString& strDecryptData, const QString& strPriKey)
{
    QByteArray priKeyArry = strPriKey.toUtf8();
    uchar* pPriKey = (uchar*)priKeyArry.data();
    BIO* pKeyBio = BIO_new_mem_buf(pPriKey, priKeyArry.length());
    if (pKeyBio == NULL){
        return "";
    }
    RSA* pRsa = RSA_new();
    pRsa = PEM_read_bio_RSAPrivateKey(pKeyBio, &pRsa, NULL, NULL);
    if ( pRsa == NULL ){
        BIO_free_all(pKeyBio);
        return "";
    }
    int nLen = RSA_size(pRsa);
    char* pClearBuf = new char[nLen];
    memset(pClearBuf, 0, nLen);

         //decrypt
    QByteArray decryptDataArry = strDecryptData.toUtf8();
    decryptDataArry = QByteArray::fromBase64(decryptDataArry);
    int nDecryptDataLen = decryptDataArry.length();
    uchar* pDecryptData = (uchar*)decryptDataArry.data();
    int nSize = RSA_private_decrypt(nDecryptDataLen,
                                    pDecryptData,
                                    (uchar*)pClearBuf,
                                    pRsa,
                                    RSA_PKCS1_PADDING);
    QString strClearData = "";
    if ( nSize >= 0 ){
        strClearData = QByteArray(pClearBuf, nSize);
    }
         // free memory
    delete pClearBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strClearData;
}

void rsa::test()
{
    QString strPriKey = "";
    QString strPubKey = "";

    createRsaKey(strPubKey, strPriKey);
    qDebug() << strPubKey << endl;
    qDebug() << strPriKey << endl;
    qDebug() << "private key encrypt, public key decrypt";
    QString strClear = "hello";
    QString strEncryptData = rsa_pri_encrypt_base64 (strClear, strPriKey);
    qDebug() << strEncryptData;
    QString strClearData = rsa_pub_decrypt_base64 (strEncryptData, strPubKey);
    qDebug() << strClearData;
    qDebug() << "public key encrypt, private key decrypt";
    strEncryptData = rsa_pub_encrypt_base64 (strClear, strPubKey);
    qDebug() << strEncryptData;
    strClearData = rsa_pri_decrypt_base64 (strEncryptData, strPriKey);
    qDebug() << strClearData;
}
