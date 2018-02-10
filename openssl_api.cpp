#include "openssl_api.h"
#include "myhelper.h"
#include <QByteArray>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <QDebug>

typedef unsigned char BYTE;

OPENSSL_API::OPENSSL_API()
{

}

static const EVP_CIPHER *  getalg(int alg, int mode , int keylen)
{
    const EVP_CIPHER * cipher = NULL;

    switch(alg)
    {
    case DES:
        switch(mode)
        {
        case ECB:
            if(keylen==8){
                cipher = EVP_des_ecb();
            }
            else if(keylen==16){
                cipher = EVP_des_ede();
            }
            else if(keylen==24){
                cipher = EVP_des_ede3();
            }
            break;
        case CBC:
            if(keylen==8){
                cipher = EVP_des_cbc();
            }
            else if(keylen==16){
                cipher = EVP_des_ede_cbc();
            }
            else if(keylen==24){
                cipher = EVP_des_ede3_cbc();
            }
            break;
        case CFB:
            if(keylen==8){
                cipher = EVP_des_cfb();
            }
            else if(keylen==16){
                cipher = EVP_des_ede_cfb();
            }
            else if(keylen==24){
                cipher = EVP_des_ede3_cfb();
            }
            break;
        case OFB:
            if(keylen==8){
                cipher = EVP_des_ofb();
            }
            else if(keylen==16){
                cipher = EVP_des_ede_ofb();
            }
            else if(keylen==24){
                cipher = EVP_des_ede3_ofb();
            }
            break;
        default:
            break;
        }
        break;

    case AES:
        switch(mode)
        {
        case ECB:
            if(keylen==16){
                cipher = EVP_aes_128_ecb();
            }
            else if(keylen==24){
                cipher = EVP_aes_192_ecb();
            }
            else if(keylen==32){
                cipher = EVP_aes_256_ecb();
            }
            break;
        case CBC:
            if(keylen==16){
                cipher = EVP_aes_128_cbc();
            }
            else if(keylen==24){
                cipher = EVP_aes_192_cbc();
            }
            else if(keylen==32){
                cipher = EVP_aes_256_cbc();
            }
            break;
        case CFB:
            if(keylen==16){
                cipher = EVP_aes_128_cfb();
            }
            else if(keylen==24){
                cipher = EVP_aes_192_cfb();
            }
            else if(keylen==32){
                cipher = EVP_aes_256_cbc();
            }
            break;
        case OFB:
            if(keylen==16){
                cipher = EVP_aes_128_ofb();
            }
            else if(keylen==24){
                cipher = EVP_aes_192_ofb();
            }
            else if(keylen==32){
                cipher = EVP_aes_256_ofb();
            }
            break;
        default:
            break;
        }
        break;

    case SM4:
        switch(mode)
        {
        case ECB:
            if(keylen==16){
                cipher = EVP_sm4_ecb();
            }
            break;
        case CBC:
            if(keylen==16){
                cipher = EVP_sm4_cbc();
            }
            break;
        case CFB:
            if(keylen==16){
                cipher = EVP_sm4_cbc();
            }
            break;
        case OFB:
            if(keylen==16){
                cipher = EVP_sm4_ofb();
            }
            break;
        default:
            break;
        }
        break;

    default:
        break;
    }

    return cipher;
}


int OPENSSL_API::enc(QString keyHex, QString ivHex, int alg, int mode, QString inHex, QString& outHex)
{

    QByteArray QbyteKey  = myHelper::hexStrToByteArray(keyHex);
    QByteArray QbyteIV  =  myHelper::hexStrToByteArray(ivHex);
    QByteArray QbyteIn  =  myHelper::hexStrToByteArray(inHex);

    int ret = 0;
    int block_size = 16;
    int inlen = QbyteIn.length();
    char* in = (char*)QbyteIn.data();
    char* out = new char[inlen+16];

    int offset = 0;
    int outlen = 0;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();


    int keylen = QbyteKey.length();

    const EVP_CIPHER *cipher = NULL;
    cipher = getalg(alg,mode,keylen);
    if(NULL==cipher){
        goto errret;
    }

    if(alg==DES)
        block_size = 8;

    if( (inlen%block_size) != 0 )
    {
        goto errret;
    }
    if( mode!=ECB && (block_size*2) !=ivHex.length() )
    {
        goto errret;
    }

    BYTE key[33];
    BYTE iv[33];
    memcpy( key, QbyteKey.data() , QbyteKey.length() );
    memcpy( iv, QbyteIV.data() , QbyteIV.length() );

    ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    if (ret != 1) goto errret;

    EVP_CIPHER_CTX_set_padding(ctx,0);//no padding

    while( offset<inlen ){
        int _len = 0;
        ret = EVP_EncryptUpdate(ctx, (unsigned char*)out + offset, &_len,
                                (unsigned char*)in + offset, block_size);
        if( ret != 1 )
            goto errret;
        offset += _len;
    }
    ret = EVP_EncryptFinal(ctx, (unsigned char*)out + offset, &outlen);
    if (ret != 1)
        goto errret;

    offset += outlen;

    outlen = offset;
    outHex = myHelper::byteArrayToHexStr( QByteArray(out,outlen) );

    EVP_CIPHER_CTX_free(ctx);
    delete[] out;
    return 0;

errret:
    EVP_CIPHER_CTX_free(ctx);
    if( out!=NULL )
        delete[] out;
    return -1;

}

int OPENSSL_API::dec(QString keyHex, QString ivHex, int alg, int mode, QString inHex, QString &outHex)
{
    QByteArray QbyteKey  = myHelper::hexStrToByteArray(keyHex);
    QByteArray QbyteIV  =  myHelper::hexStrToByteArray(ivHex);
    QByteArray QbyteIn  =  myHelper::hexStrToByteArray(inHex);

    int offset = 0;
    int outlen = 0;

    int ret = 0;
    int block_size = 16;
    int inlen = QbyteIn.length();
    char* in = (char*)QbyteIn.data();
    char* out = new char[inlen+16];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx,0);//no padding

    int keylen = QbyteKey.length();

    const EVP_CIPHER *cipher = NULL;
    cipher = getalg(alg,mode,keylen);
    if(NULL==cipher){
        goto errret;
    }

    if(alg==DES)
        block_size = 8;

    if( (inlen%block_size) != 0 )
    {
        goto errret;
    }
    if( mode!=ECB && (block_size*2) !=ivHex.length() )
    {
        goto errret;
    }

    BYTE key[33];
    BYTE iv[33];
    memcpy( key, QbyteKey.data() , QbyteKey.length() );
    memcpy( iv, QbyteIV.data() , QbyteIV.length() );

    ret = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    if (ret != 1) goto errret;

    EVP_CIPHER_CTX_set_padding(ctx,0);//no padding



#if 1
    while( offset<inlen ){
        int _len = 0;
        ret = EVP_DecryptUpdate(ctx, (unsigned char*)out + offset, &_len,
                                (unsigned char*)in + offset, inlen);
        if( ret != 1 )
            goto errret;
        offset += _len;

    }
#endif

//#if 0
//    int _len = 0;
//    ret = EVP_DecryptUpdate(ctx, (unsigned char*)out , &_len,
//                            (unsigned char*)in , inlen);
//    if( ret != 1 )
//        goto errret;
//    offset += _len;
//#endif

    ret = EVP_DecryptFinal(ctx, (unsigned char*)out + offset, &outlen);
    if (ret != 1)
        goto errret;

    offset += outlen;


    outlen = offset;
    outHex = myHelper::byteArrayToHexStr( QByteArray(out,outlen) );

    EVP_CIPHER_CTX_free(ctx);
    delete[] out;
    return 0;

errret:
    EVP_CIPHER_CTX_free(ctx);

//    {  填充问题: 默认使用pkcs填充, 如果随便使用数据进行解密,则去填充失败导致解密失败
        //错误描述为 digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:crypto\evp\evp_enc.c:527:
//        BIO *b = BIO_new(BIO_s_mem());
//        ERR_print_errors(b);
//        char errmsg[256] = {0};
//        BIO_read(b, errmsg, BIO_ctrl_pending(b) );
//        //QDebug::QDebug(errmsg);
//        qDebug() << errmsg;
//    }

    if( out!=NULL )
        delete[] out;
    return -1;
}



int OPENSSL_API::genrsa(QString bits, QString e, QString &outPKDer, QString &outVKDer)
{
    int ibits = bits.toInt();
    RSA * rsakey = RSA_new();
    BIGNUM* pBN=  BN_new();
    EVP_PKEY *pkey = EVP_PKEY_new();

    QByteArray bytepk;
    QByteArray bytevk;

    BN_dec2bn(&pBN, e.toStdString().c_str() );

    if ( 1 != RSA_generate_key_ex(rsakey,ibits,pBN, NULL) ){
        BN_free(pBN);
        RSA_free(rsakey);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_set1_RSA(pkey,rsakey);

    unsigned char *pk = NULL;
    unsigned char *vk = NULL;
    int pklen = i2d_PublicKey(pkey, &pk);
    int vklen = i2d_PrivateKey(pkey,&vk);

    bytepk.append((char*)pk, pklen);
    bytevk.append((char*)vk, vklen);

    outPKDer.clear();
    outPKDer.append( bytepk.toHex() );
    outVKDer.clear();
    outVKDer.append( bytevk.toHex() );

    free(pk);
    free(vk);
    BN_free(pBN);
    RSA_free(rsakey);
    EVP_PKEY_free(pkey);
    return 0;
}






