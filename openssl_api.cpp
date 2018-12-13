#include "openssl_api.h"
#include "myhelper.h"
#include <QByteArray>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/sm3.h>
#include <openssl/sm2.h>
#include <openssl/objects.h>

#include <QDebug>

namespace GMSSLST {

struct SM2CiphertextValue_st
{
    BIGNUM *xCoordinate;
    BIGNUM *yCoordinate;
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *ciphertext;
};

struct asn1_string_st
{
    int length;
    int type;
    unsigned char *data;
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
    long flags;
};
}

typedef unsigned char BYTE;
#define SM2RAWALG    //use sm2 alg directly, not by EVP*


#define PRINT_ERROR \
{\
    BIO *__b = BIO_new(BIO_s_mem());\
    ERR_print_errors(__b);\
    char errmsg[1024] = {0};\
    BIO_read(__b, errmsg, BIO_ctrl_pending(__b));\
    qDebug() << errmsg;\
    }


OPENSSL_API::OPENSSL_API()
{

}

static const EVP_CIPHER   *getalg(int alg, int mode, int keylen)
{
    const EVP_CIPHER *cipher = nullptr;

    switch (alg) {
    case DES:
        switch (mode) {
        case ECB:
            if (keylen == 8)
                cipher = EVP_des_ecb();
            else if (keylen == 16)
                cipher = EVP_des_ede();
            else if (keylen == 24)
                cipher = EVP_des_ede3();
            break;
        case CBC:
            if (keylen == 8)
                cipher = EVP_des_cbc();
            else if (keylen == 16)
                cipher = EVP_des_ede_cbc();
            else if (keylen == 24)
                cipher = EVP_des_ede3_cbc();
            break;
        case CFB:
            if (keylen == 8)
                cipher = EVP_des_cfb();
            else if (keylen == 16)
                cipher = EVP_des_ede_cfb();
            else if (keylen == 24)
                cipher = EVP_des_ede3_cfb();
            break;
        case OFB:
            if (keylen == 8)
                cipher = EVP_des_ofb();
            else if (keylen == 16)
                cipher = EVP_des_ede_ofb();
            else if (keylen == 24)
                cipher = EVP_des_ede3_ofb();
            break;
        default:
            break;
        }
        break;

    case AES:
        switch (mode) {
        case ECB:
            if (keylen == 16)
                cipher = EVP_aes_128_ecb();
            else if (keylen == 24)
                cipher = EVP_aes_192_ecb();
            else if (keylen == 32)
                cipher = EVP_aes_256_ecb();
            break;
        case CBC:
            if (keylen == 16)
                cipher = EVP_aes_128_cbc();
            else if (keylen == 24)
                cipher = EVP_aes_192_cbc();
            else if (keylen == 32)
                cipher = EVP_aes_256_cbc();
            break;
        case CFB:
            if (keylen == 16)
                cipher = EVP_aes_128_cfb();
            else if (keylen == 24)
                cipher = EVP_aes_192_cfb();
            else if (keylen == 32)
                cipher = EVP_aes_256_cbc();
            break;
        case OFB:
            if (keylen == 16)
                cipher = EVP_aes_128_ofb();
            else if (keylen == 24)
                cipher = EVP_aes_192_ofb();
            else if (keylen == 32)
                cipher = EVP_aes_256_ofb();
            break;
        default:
            break;
        }
        break;

    case SM4:
        switch (mode) {
        case ECB:
            if (keylen == 16)
                cipher = EVP_sm4_ecb();
            break;
        case CBC:
            if (keylen == 16)
                cipher = EVP_sm4_cbc();
            break;
        case CFB:
            if (keylen == 16)
                cipher = EVP_sm4_cbc();
            break;
        case OFB:
            if (keylen == 16)
                cipher = EVP_sm4_ofb();
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


int OPENSSL_API::enc(QString keyHex, QString ivHex, int alg, int mode, QString inHex, QString &outHex)
{

    QByteArray QbyteKey  = myHelper::hexStrToByteArray(keyHex);
    QByteArray QbyteIV  =  myHelper::hexStrToByteArray(ivHex);
    QByteArray QbyteIn  =  myHelper::hexStrToByteArray(inHex);

    int ret = 0;
    int block_size = 16;
    int inlen = QbyteIn.size();
    const unsigned char *in = reinterpret_cast<const unsigned char *>(QbyteIn.data());
    unsigned char *out = new unsigned char[inlen + 16];

    int offset = 0;
    int outlen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    int keylen = QbyteKey.length();

    const EVP_CIPHER *cipher = nullptr;
    cipher = getalg(alg, mode, keylen);
    if (nullptr == cipher)
        goto errret;

    if (alg == DES)
        block_size = 8;

    if ((inlen % block_size) != 0)
        goto errret;
    if (mode != ECB && (block_size * 2) != ivHex.length())
        goto errret;

    BYTE key[33];
    BYTE iv[33];
    memcpy(key, QbyteKey.data(), QbyteKey.size());
    memcpy(iv, QbyteIV.data(), QbyteIV.size());

    ret = EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
    if (ret != 1) goto errret;

    EVP_CIPHER_CTX_set_padding(ctx, 0); //no padding

    while (offset < inlen) {
        int _len = 0;
        ret = EVP_EncryptUpdate(ctx, out + offset, &_len,
                                in + offset, block_size);
        if (ret != 1)
            goto errret;
        offset += _len;
    }
    ret = EVP_EncryptFinal(ctx, out + offset, &outlen);
    if (ret != 1)
        goto errret;

    offset += outlen;

    outlen = offset;
    outHex = QByteArray(reinterpret_cast<const char *>(out), outlen).toHex().toUpper();

    EVP_CIPHER_CTX_free(ctx);
    delete[] out;
    return 0;

errret:
    EVP_CIPHER_CTX_free(ctx);
    if (out != nullptr)
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
    const unsigned char *in = reinterpret_cast<const unsigned char *>(QbyteIn.data());
    unsigned char *out = new unsigned char[inlen + 16];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);//no padding

    int keylen = QbyteKey.length();

    const EVP_CIPHER *cipher = nullptr;
    cipher = getalg(alg, mode, keylen);
    if (nullptr == cipher)
        goto errret;

    if (alg == DES)
        block_size = 8;

    if ((inlen % block_size) != 0)
        goto errret;
    if (mode != ECB && (block_size * 2) != ivHex.length())
        goto errret;

    BYTE key[33];
    BYTE iv[33];
    memcpy(key, QbyteKey.data(), QbyteKey.size());
    memcpy(iv, QbyteIV.data(), QbyteIV.size());

    ret = EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv);
    if (ret != 1) goto errret;

    EVP_CIPHER_CTX_set_padding(ctx, 0); //no padding

#if 1
    while (offset < inlen) {
        int _len = 0;
        ret = EVP_DecryptUpdate(ctx, out + offset, &_len,
                                in + offset, inlen);
        if (ret != 1)
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

    ret = EVP_DecryptFinal(ctx, out + offset, &outlen);
    if (ret != 1)
        goto errret;

    offset += outlen;


    outlen = offset;
    outHex = QByteArray(reinterpret_cast<const char *>(out), outlen).toHex().toUpper();

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

    if (out != nullptr)
        delete[] out;
    return -1;
}



int OPENSSL_API::genrsa(QString bits, QString e, QString &outPKDer, QString &outVKDer)
{
    int ibits = bits.toInt();
    RSA *rsakey = RSA_new();
    BIGNUM *pBN =  BN_new();
    EVP_PKEY *pkey = EVP_PKEY_new();

    QByteArray bytepk;
    QByteArray bytevk;

    unsigned char *pk = nullptr;
    unsigned char *vk = nullptr;

    BN_dec2bn(&pBN, e.toStdString().c_str());

    if (1 != RSA_generate_key_ex(rsakey, ibits, pBN, nullptr)) {
        BN_free(pBN);
        RSA_free(rsakey);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_set1_RSA(pkey, rsakey);


    int pklen = i2d_PublicKey(pkey, &pk);
    int vklen = i2d_PrivateKey(pkey, &vk);

    bytepk.append(reinterpret_cast<const char *>(pk), pklen);
    bytevk.append(reinterpret_cast<const char *>(vk), vklen);

    outPKDer.clear();
    outPKDer.append(bytepk.toHex());
    outVKDer.clear();
    outVKDer.append(bytevk.toHex());

#ifndef WIN32  //在win10下, debug版本 此处导致崩溃,但没有此处会有内存泄露?
    free(pk);
    free(vk);
#endif

    BN_free(pBN);
    RSA_free(rsakey);
    EVP_PKEY_free(pkey);
    return 0;
}

int OPENSSL_API::rsa_pkenc(QString derpk, QString in, int padding, QString &out)
{
    RSA *rsa = nullptr;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex(in.toUtf8());
    unsigned char *to = nullptr;
    QByteArray outdata;

    QByteArray pk = QByteArray::fromHex(derpk.toUtf8());
    const unsigned char *t = reinterpret_cast<const unsigned char *>(pk.data());
    rsa = d2i_RSAPublicKey(nullptr, &t, pk.length());
    if (rsa == nullptr)
        goto errret;

    flen = RSA_size(rsa);//模长
    switch (padding) {
    case RSA_PKCS1_PADDING:
    case RSA_SSLV23_PADDING:
        flen -= 11;
        break;
    case RSA_NO_PADDING:
        break;
    case RSA_X931_PADDING:
        flen -= 2;
        break;
    }

    if (indata.length() > flen)
        goto errret;

    to = new unsigned char[flen + 12];
    ret = RSA_public_encrypt(indata.length(), reinterpret_cast<unsigned char *>(indata.data()), to, rsa, padding);
    if (ret != RSA_size(rsa))
        goto errret;

    outdata.append(reinterpret_cast<const char *>(to), RSA_size(rsa));
    out.append(outdata.toHex());

    RSA_free(rsa);
    delete[] to;
    return 0;

errret:
    RSA_free(rsa);
    if (to)
        delete[] to;
    return -1;
}

int OPENSSL_API::rsa_vkdec(QString dervk, QString in, int padding, QString &out)
{
    RSA *rsa = nullptr;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex(in.toUtf8());
    unsigned char *to = nullptr;
    QByteArray outdata;

    QByteArray vk =  QByteArray::fromHex(dervk.toUtf8());
    const unsigned char *t = reinterpret_cast<const unsigned char *>(vk.data());
    rsa = d2i_RSAPrivateKey(nullptr, &t, vk.length());
    if (rsa == nullptr)
        goto errret;

    flen = RSA_size(rsa);//模长
    if (indata.length() != flen)
        goto errret;

    to = new unsigned char[flen + 12];
    ret = RSA_private_decrypt(flen, reinterpret_cast<const unsigned char *>(indata.data()), to, rsa, padding);
    if (ret <= 0)
        goto errret;

    outdata.append(reinterpret_cast<const char *>(to), ret);
    out.append(outdata.toHex());

    RSA_free(rsa);
    delete[] to;
    return 0;

errret:
    RSA_free(rsa);
    if (to)
        delete[] to;
    return -1;
}

int OPENSSL_API::rsa_vkenc(QString dervk, QString in, int padding, QString &out)
{
    RSA *rsa = nullptr;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex(in.toUtf8());
    unsigned char *to = nullptr;
    QByteArray outdata;

    QByteArray vk =  QByteArray::fromHex(dervk.toUtf8());
    const unsigned char *t = reinterpret_cast<const unsigned char *>(vk.data());
    rsa = d2i_RSAPrivateKey(nullptr, &t, vk.length());
    if (rsa == nullptr)
        goto errret;

    flen = RSA_size(rsa);//模长
    switch (padding) {
    case RSA_PKCS1_PADDING:
    case RSA_SSLV23_PADDING:
        flen -= 11;
        break;
    case RSA_NO_PADDING:
        break;
    case RSA_X931_PADDING:
        flen -= 2;
        break;
    }

    if (indata.length() > flen)
        goto errret;

    to = new unsigned char[flen + 12];
    ret = RSA_private_encrypt(indata.length(), (unsigned char *)indata.data(), to, rsa, padding);
    if (ret !=  RSA_size(rsa))
        goto errret;

    outdata.append((char *)to, ret);
    out.append(outdata.toHex());

    RSA_free(rsa);
    delete[] to;
    return 0;
errret:
    RSA_free(rsa);
    if (to)
        delete[] to;
    return -1;
}

int OPENSSL_API::rsa_pkdec(QString derpk, QString in, int padding, QString &out)
{
    RSA *rsa = nullptr;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex(in.toUtf8());
    unsigned char *to = nullptr;
    QByteArray outdata;

    QByteArray pk =  QByteArray::fromHex(derpk.toUtf8());
    const unsigned char *t = (const unsigned char *)pk.data() ;
    rsa = d2i_RSAPublicKey(nullptr, &t, pk.length());
    if (rsa == nullptr)
        goto errret;

    flen = RSA_size(rsa);//模长
    if (indata.length() != flen)
        goto errret;

    to = new unsigned char[flen + 12];
    ret = RSA_public_decrypt(indata.length(), (unsigned char *)indata.data(), to, rsa, padding);
    if (ret <= 0)
        goto errret;

    outdata.append((char *)to, ret);
    out.append(outdata.toHex());

    RSA_free(rsa);
    delete[] to;
    return 0;


errret:
    RSA_free(rsa);
    if (to)
        delete[] to;
    return -1;
}


/*
alg 1:md5 2:sm3 3:ISO10118-2 4:sha1 5:sha224 6:sha256 7:sha384 8:sha512
*/
int OPENSSL_API::hash(QString inHex, int alg, QString &out)
{
    QByteArray indata = QByteArray::fromHex(inHex.toUtf8());
    QByteArray outdata;

    const EVP_MD      *md = nullptr;
    unsigned char mdout[128] = {0};
    unsigned int mdlen = 0;

    switch (alg) {
    case 1:
        md = EVP_md5();
        break;
    case 2:
        md = EVP_sm3();
        break;
    case 3:
        md = EVP_mdc2();
        break;
    case 4:
        md = EVP_sha1();
        break;
    case 5:
        md = EVP_sha224();
        break;
    case 6:
        md = EVP_sha256();
        break;
    case 7:
        md = EVP_sha384();
        break;
    case 8:
        md = EVP_sha512();
        break;
    default:
        return -1;
    }

    memset(mdout, 0, sizeof(mdout));
    EVP_Digest(indata.data(), indata.length(), (unsigned char *)mdout, (unsigned int *)&mdlen, md, nullptr);
    if (mdlen == 0)
        return -1;

    outdata.append((char *)mdout, mdlen);

    out = outdata.toHex();

    return mdlen;
}

static EC_KEY *new_ec_key(const EC_GROUP *group,
                          const char *sk, const char *xP, const char *yP)
{
    int ok = 0;
    EC_KEY *ec_key = nullptr;
    BIGNUM *d = nullptr;
    BIGNUM *x = nullptr;
    BIGNUM *y = nullptr;

    OPENSSL_assert(group);

    if (!(ec_key = EC_KEY_new())) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }
    if (!EC_KEY_set_group(ec_key, group)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }
    if (sk) {
        if (!BN_hex2bn(&d, sk)) {
            qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
            goto end;
        }
        if (!EC_KEY_set_private_key(ec_key, d)) {
            qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
            goto end;
        }
    }

    if (xP && yP) {
        if (!BN_hex2bn(&x, xP)) {
            qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
            goto end;
        }
        if (!BN_hex2bn(&y, yP)) {
            qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
            goto end;
        }
        if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
            qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
            goto end;
        }
    }
    ok = 1;
end:
    if (d) BN_free(d);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (!ok && ec_key) {
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }
    return ec_key;
}


int OPENSSL_API::sm2gen(QString &p_x, QString &p_y, QString &d)
{
    int ret = 0;

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    ret = EC_KEY_generate_key(ec_key);
    if (ret != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return -1;
    }

    const EC_POINT *ecpoint =  EC_KEY_get0_public_key(ec_key);
    if (!ecpoint) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return -1;
    }

    char *pHexPoint = nullptr;
    pHexPoint = EC_POINT_point2hex(group, ecpoint, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    if (!ecpoint) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return -1;
    }

    char pxhex[65] = {0};
    char pyhex[65] = {0};
    memcpy(pxhex, pHexPoint + 2,      64);
    memcpy(pyhex, pHexPoint + 2 + 64, 64);

    p_x.append(pxhex);
    p_y.append(pyhex);

    const BIGNUM *bnD = EC_KEY_get0_private_key(ec_key);
    char *d_hex = BN_bn2hex(bnD);
    d.append(d_hex);
    OPENSSL_free(d_hex);
    OPENSSL_free(pHexPoint);
    EC_GROUP_free(group);
    EC_KEY_free(ec_key);
    return 0;
}


int OPENSSL_API::sm2enc(QString p_x, QString p_y, QString msg, QString &hex)
{
    if (msg.isEmpty())
        return 0;

    int ret = -1;

    EC_GROUP *group = nullptr;
    EC_KEY  *ec_key = nullptr;
    unsigned char out[128 + 256] = { 0 };
    unsigned char *p = out;
    int len;

    SM2CiphertextValue *cv = nullptr;
    QByteArray bytein;
    QByteArray ba_out;

    //获取ECC公钥结构
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }

    if (!(ec_key = new_ec_key(group, nullptr, p_x.toStdString().c_str(), p_y.toStdString().c_str()))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }

    //len = M.length() * 2 + 256; // M.length() * 2 -- Ascii->Hex
    //out = (unsigned char*)OPENSSL_zalloc(len);

    //获取EVP密钥结构
#ifndef SM2RAWALG
    EVP_PKEY_CTX *ctx = NULL;
    //EVP_PKEY *key = NULL;
    key = EVP_PKEY_new();
    if (1 != EVP_PKEY_set1_EC_KEY(key, ec_key))
        goto end;
    ctx = EVP_PKEY_CTX_new(key, NULL);

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        goto end;
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, (unsigned char *)bytein.data(), bytein.length());
    if (ret <= 0) {
        PRINT_ERROR;
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
#else
    //SM2_encrypt(NID_sm3, (const unsigned char *)M.toStdString().c_str(), M.length(), out, &len, ec_key);
    if (!(cv = SM2_do_encrypt(EVP_sm3(),
                              reinterpret_cast<const unsigned char *>(msg.toStdString().c_str()),
                              static_cast<size_t>(msg.size()), ec_key))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }

    if ((len = i2o_SM2CiphertextValue(group, cv, &p)) <= 0) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }
#endif
    ba_out.append(reinterpret_cast<const char *>(out), len);
    hex.append(ba_out.toHex());
    ret = 1;
end:
    if (group) EC_GROUP_free(group);
    if (ec_key) EC_KEY_free(ec_key);
    if (cv) SM2CiphertextValue_free(cv);
    return ret;
}

int OPENSSL_API::sm2dec(QString d, QString hex, QString &msg)
{
    if (d.isEmpty() || hex.isEmpty())
        return 0;

    int ret = -1;
    EC_GROUP *group = nullptr;
    EC_KEY  *ec_key = nullptr;
    SM2CiphertextValue *cv = nullptr;

    unsigned char out[128] = { 0 };
    const unsigned char *p = nullptr;
    size_t len;

    QByteArray ba_msg = QByteArray::fromHex(hex.toUtf8());
    //获取ECC公钥结构
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }

    if (!(ec_key = new_ec_key(group, d.toStdString().c_str(), nullptr, nullptr))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto end;
    }
#ifndef SM2RAWALG
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new(key, NULL);
    //获取EVP密钥结构
    key = EVP_PKEY_new();
    if (1 != EVP_PKEY_set1_EC_KEY(key, ec_key))
        goto end;
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        goto end;
    ret = EVP_PKEY_decrypt(ctx, out, &outlen, derin, derin_len);
    if (ret <= 0) {
        PRINT_ERROR;
        goto end;
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
#else
    /* test decrypt */
    p = reinterpret_cast<const unsigned char *>(ba_msg.data());
    cv = o2i_SM2CiphertextValue(group, EVP_sm3(), nullptr, &p, ba_msg.size());
    ret = SM2_do_decrypt(EVP_sm3(), cv, out, &len, ec_key);
#endif
    msg = QString::fromLocal8Bit(reinterpret_cast<const char *>(out), static_cast<int>(len));
    ret = 1;
end:
    if (group) EC_GROUP_free(group);
    if (ec_key) EC_KEY_free(ec_key);
    if (cv) SM2CiphertextValue_free(cv);
    return ret;
}

int OPENSSL_API::sm2sign(QString d, QString p_x, QString p_y,
                         QString uid, QString msg, QString &hex)
{
    if (d.isEmpty() || p_x.isEmpty() || p_y.isEmpty())
        return 0;

    int ret = -1;

    EC_GROUP *group = nullptr;
    EC_KEY  *ec_key = nullptr;
    ECDSA_SIG *sm2sig = nullptr;

    unsigned char dgst[EVP_MAX_MD_SIZE] = {0}, sign[256] = {0};
    size_t dgstlen, signlen;
    const unsigned char *p = nullptr;

    const BIGNUM *sign_r = nullptr, *sign_s = nullptr;
    char *rr = nullptr, *ss = nullptr;

    //获取ECC公钥结构
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }

    if (!(ec_key = new_ec_key(group, d.toStdString().c_str(),
                              p_x.toStdString().c_str(), p_y.toStdString().c_str()))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }

    // debug 输入密钥对信息 以下调试语句不能要，否则会出现no OPENSSL_Applink错误
    // EC_KEY_print_fp(stdout, ec_key, 4);

    if (1 != SM2_compute_id_digest(EVP_sm3(), uid.toStdString().c_str(),
                                   static_cast<size_t>(uid.length()), dgst, &dgstlen, ec_key)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    if (1 != SM2_compute_message_digest(EVP_sm3(), EVP_sm3(),
                                        reinterpret_cast<const unsigned char *>(msg.toStdString().c_str()),
                                        static_cast<size_t>(msg.length()),
                                        uid.toStdString().c_str(),
                                        static_cast<size_t>(uid.length()),
                                        dgst, &dgstlen, ec_key)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    // debug 输出原始uid及uid摘要
    {
        QString zid = QByteArray(reinterpret_cast<const char *>(dgst),
                                 static_cast<int>(dgstlen)).toHex();
        qDebug() << QString("uid=%1, msg=%2").arg(uid, msg);
        qDebug() << QString("digest=%1").arg(zid);
    }
    /* 签名 */
    if (1 != SM2_sign(NID_undef, dgst, static_cast<int>(dgstlen), sign, &signlen, ec_key)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }

    p = sign;
    if (!(sm2sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(signlen)))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }

    ECDSA_SIG_get0(sm2sig, &sign_r, &sign_s);
    rr = BN_bn2hex(sign_r);
    qDebug() << rr;
    ss = BN_bn2hex(sign_s);
    qDebug() << ss;
    hex.append(rr);
    hex.append(ss);

    ret = 1;
err:
    if (group) EC_GROUP_free(group);
    if (ec_key) EC_KEY_free(ec_key);
    if (sm2sig) ECDSA_SIG_free(sm2sig);

    if (rr) OPENSSL_free(rr);
    if (ss) OPENSSL_free(ss);

    return ret;
}

int OPENSSL_API::sm2verify(QString p_x, QString p_y,
                           QString uid, QString msg, QString hex)
{
    if (p_x.isEmpty() || p_y.isEmpty() ||  uid.isEmpty() || hex.isEmpty())
        return 0;

    int ret = -1;
    EC_GROUP *group = nullptr;
    EC_KEY  *ec_key = nullptr; // 公钥
    ECDSA_SIG *sm2sig = nullptr;
    unsigned char dgst[EVP_MAX_MD_SIZE] = {0}, sign[256] = {0};
    unsigned char *p = nullptr;
    size_t dgst_len;
    int rrss_len, sign_len;
    BIGNUM *sign_r = nullptr, *sign_s = nullptr;

    //获取ECC公钥结构
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }

    if (!(ec_key = new_ec_key(group, nullptr, p_x.toStdString().c_str(), p_y.toStdString().c_str()))) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    // 计算杂凑值
    if (1 != SM2_compute_id_digest(EVP_sm3(), uid.toStdString().c_str(),
                                   static_cast<size_t>(uid.length()), dgst, &dgst_len, ec_key)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    if (1 != SM2_compute_message_digest(EVP_sm3(), EVP_sm3(),
                                        reinterpret_cast<const unsigned char *>(msg.toStdString().c_str()),
                                        static_cast<size_t>(msg.length()),
                                        uid.toStdString().c_str(),
                                        static_cast<size_t>(uid.length()),
                                        dgst, &dgst_len, ec_key)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    // debug 输出原始uid及uid摘要
    {
        QString zid = QByteArray(reinterpret_cast<const char *>(dgst),
                                 static_cast<int>(dgst_len)).toHex();
        qDebug() << QString("uid=%1, msg=%2").arg(uid, msg);
        qDebug() << QString("digest=%1").arg(zid);
    }

    //获取签名值
    rrss_len = hex.length() / 2;
    BN_hex2bn(&sign_r, hex.left(rrss_len).toStdString().c_str());
    if (!sign_r) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    BN_hex2bn(&sign_s, hex.right(rrss_len).toStdString().c_str());
    if (!sign_r) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }

    sm2sig = ECDSA_SIG_new();
    if (0 == ECDSA_SIG_set0(sm2sig, sign_r, sign_s)) {
        qDebug() << QString("error: %1 %2").arg(__FUNCTION__).arg(__LINE__);
        goto err;
    }
    p = sign;
    sign_len = i2d_ECDSA_SIG(sm2sig, &p);

    // 验签
    if (1 != SM2_verify(NID_undef, dgst, static_cast<int>(dgst_len), sign, sign_len, ec_key)) {
        qDebug() << "☆☆验签失败☆☆";
        goto err;
    } else
        qDebug() << "★★验签成功★★";
    ret = 1;
err:
    if (group) EC_GROUP_free(group);
    if (ec_key) EC_KEY_free(ec_key);
    if (sm2sig) ECDSA_SIG_free(sm2sig);
    //if (sign_r) BN_free(sign_r);
    //if (sign_s) BN_free(sign_s);
    return ret;
}
