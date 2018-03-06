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

struct SM2CiphertextValue_st{
    BIGNUM *xCoordinate;
    BIGNUM *yCoordinate;
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *ciphertext;
};

struct asn1_string_st {
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

#define PRINT_ERROR() \
    BIO *__b = BIO_new(BIO_s_mem());\
    ERR_print_errors(__b);\
    char errmsg[1024] = {0};\
    BIO_read(__b, errmsg, BIO_ctrl_pending(__b) );\
    QDebug::QDebug(errmsg);\
    qDebug() << errmsg;




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

    unsigned char *pk = NULL;
    unsigned char *vk = NULL;

    BN_dec2bn(&pBN, e.toStdString().c_str() );

    if ( 1 != RSA_generate_key_ex(rsakey,ibits,pBN, NULL) ){
        BN_free(pBN);
        RSA_free(rsakey);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_set1_RSA(pkey,rsakey);


    int pklen = i2d_PublicKey(pkey, &pk);
    int vklen = i2d_PrivateKey(pkey,&vk);

    bytepk.append((char*)pk, pklen);
    bytevk.append((char*)vk, vklen);

    outPKDer.clear();
    outPKDer.append( bytepk.toHex() );
    outVKDer.clear();
    outVKDer.append( bytevk.toHex() );

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
    RSA * rsa = NULL;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex( in.toUtf8() );
    unsigned char *to = NULL;
    QByteArray outdata;

    QByteArray pk =  QByteArray::fromHex(derpk.toUtf8());
    const unsigned char *t =  (const unsigned char*)pk.data() ;
    rsa = d2i_RSAPublicKey(NULL,&t, pk.length());
    if( rsa == NULL ){
        goto errret;
    }

    flen = RSA_size(rsa);//模长
    switch(padding)
    {
    case RSA_PKCS1_PADDING:
    case RSA_SSLV23_PADDING:
        flen -= 11;break;
    case RSA_NO_PADDING:
        break;
    case RSA_X931_PADDING:
        flen -= 2;break;
    }

    if( indata.length() > flen ){
        goto errret;
    }

    to = new unsigned char[flen+12];
    ret = RSA_public_encrypt(indata.length(), (unsigned char*)indata.data(),to,rsa,padding);
    if(ret != RSA_size(rsa) ){
        goto errret;
    }

    outdata.append((char*)to,RSA_size(rsa));
    out.append( outdata.toHex() );

    RSA_free(rsa);
    delete[] to;
    return 0;


errret:
    RSA_free(rsa);
    if( to ){
        delete[] to;
    }
    return -1;
}

int OPENSSL_API::rsa_vkdec(QString dervk, QString in, int padding, QString &out)
{
    RSA * rsa = NULL;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex( in.toUtf8() );
    unsigned char *to = NULL;
    QByteArray outdata;

    QByteArray vk =  QByteArray::fromHex(dervk.toUtf8());
    const unsigned char *t =  (const unsigned char*)vk.data() ;
    rsa = d2i_RSAPrivateKey(NULL,&t, vk.length());
    if( rsa == NULL ){
        goto errret;
    }

    flen = RSA_size(rsa);//模长
    if( indata.length() != flen ){
        goto errret;
    }

    to = new unsigned char[flen+12];
    ret = RSA_private_decrypt(flen, (unsigned char*)indata.data(),to,rsa,padding);
    if(ret <=0  ){
        goto errret;
    }

    outdata.append((char*)to,ret);
    out.append( outdata.toHex() );

    RSA_free(rsa);
    delete[] to;
    return 0;


errret:
    RSA_free(rsa);
    if( to ){
        delete[] to;
    }
    return -1;
}


int OPENSSL_API::rsa_vkenc(QString dervk, QString in, int padding, QString &out)
{
    RSA * rsa = NULL;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex( in.toUtf8() );
    unsigned char *to = NULL;
    QByteArray outdata;

    QByteArray vk =  QByteArray::fromHex(dervk.toUtf8());
    const unsigned char *t =  (const unsigned char*)vk.data() ;
    rsa = d2i_RSAPrivateKey(NULL,&t, vk.length());
    if( rsa == NULL ){
        goto errret;
    }

    flen = RSA_size(rsa);//模长
    switch(padding)
    {
    case RSA_PKCS1_PADDING:
    case RSA_SSLV23_PADDING:
        flen -= 11;break;
    case RSA_NO_PADDING:
        break;
    case RSA_X931_PADDING:
        flen -= 2;break;
    }

    if( indata.length() > flen ){
        goto errret;
    }

    to = new unsigned char[flen+12];
    ret = RSA_private_encrypt(indata.length(), (unsigned char*)indata.data(),to,rsa,padding);
    if( ret !=  RSA_size(rsa)){
        goto errret;
    }

    outdata.append((char*)to,ret);
    out.append( outdata.toHex() );

    RSA_free(rsa);
    delete[] to;
    return 0;


errret:
    RSA_free(rsa);
    if( to ){
        delete[] to;
    }
    return -1;
}

int OPENSSL_API::rsa_pkdec(QString derpk, QString in, int padding, QString &out)
{
    RSA * rsa = NULL;
    int ret = 0;
    int flen = 0;
    QByteArray indata = QByteArray::fromHex( in.toUtf8() );
    unsigned char *to = NULL;
    QByteArray outdata;

    QByteArray pk =  QByteArray::fromHex(derpk.toUtf8());
    const unsigned char *t =  (const unsigned char*)pk.data() ;
    rsa = d2i_RSAPublicKey(NULL,&t, pk.length());
    if( rsa == NULL ){
        goto errret;
    }

    flen = RSA_size(rsa);//模长
    if( indata.length() != flen ){
        goto errret;
    }

    to = new unsigned char[flen+12];
    ret = RSA_public_decrypt(indata.length(), (unsigned char*)indata.data(),to,rsa,padding);
    if(ret <=0  ){
        goto errret;
    }

    outdata.append((char*)to,ret );
    out.append( outdata.toHex() );

    RSA_free(rsa);
    delete[] to;
    return 0;


errret:
    RSA_free(rsa);
    if( to ){
        delete[] to;
    }
    return -1;
}





/*
alg 1:md5 2:sm3 3:ISO10118-2 4:sha1 5:sha224 6:sha256 7:sha384 8:sha512
*/
int OPENSSL_API::hash(QString inHex, int alg, QString &out)
{
    QByteArray indata = QByteArray::fromHex( inHex.toUtf8() );
    QByteArray outdata;

    const EVP_MD      *md = NULL;
    unsigned char mdout[128] = {0};
    unsigned int mdlen = 0;

    switch(alg)
    {
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

    memset(mdout,0,sizeof(mdout));
    EVP_Digest(indata.data(),indata.length(),(unsigned char *)mdout,(unsigned int *)&mdlen,md, NULL);
    if(mdlen==0)
        return -1;

    outdata.append((char*)mdout , mdlen);

    out = outdata.toHex();

    return mdlen;
}


int OPENSSL_API::gensm2(QString &xp, QString &yp, QString &dp)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;

    int nid = NID_sm2p256v1;

    ec_key = EC_KEY_new_by_curve_name(nid);
    group = EC_GROUP_new_by_curve_name(nid);

    ret = EC_KEY_generate_key(ec_key);
    if(ret!=1){
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return -1;
    }

    const EC_POINT *ecpoint =  EC_KEY_get0_public_key(ec_key);
    if( !ecpoint ){
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return -1;
    }


    char *pHexPoint = NULL;
    pHexPoint = EC_POINT_point2hex(group,ecpoint,POINT_CONVERSION_UNCOMPRESSED,NULL);
    if( !ecpoint ){
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return -1;
    }

    char pxhex[65] = {0};
    char pyhex[65] = {0};
    memcpy(pxhex,pHexPoint + 2,   64);
    memcpy(pyhex,pHexPoint + 2+64,64);

    xp.append(pxhex);
    yp.append(pyhex);

    const BIGNUM *bnD =  EC_KEY_get0_private_key(ec_key);
    char *pdHex = NULL;
    pdHex = BN_bn2hex(bnD);

    dp.append(pdHex);

    OPENSSL_free(pdHex);
    OPENSSL_free(pHexPoint);
    EC_GROUP_free(group);
    EC_KEY_free(ec_key);
    return 0;
}





int OPENSSL_API::sm2enc(QString px ,QString py  , QString inHex, QString &outHex)
{
    if(inHex.isEmpty()){
        return 0;
    }

    int ret = -1;

    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *bnx = NULL;
    BIGNUM *bny = NULL;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *out;
    SM2CiphertextValue* asn1decode = NULL;
    QByteArray byteout;
    QByteArray bytein;
    QByteArray bytetmp;

     //获取ECC公钥结构
    int nid = NID_sm2p256v1;
    group = EC_GROUP_new_by_curve_name(nid);
    point = EC_POINT_new(group);
    bnx = BN_new();
    bny = BN_new();
    BN_hex2bn(&bnx, px.toStdString().c_str() );
    BN_hex2bn(&bny, py.toStdString().c_str() );

    if( 1 != EC_POINT_set_affine_coordinates_GFp(group,point,bnx,bny,NULL))
    {
        goto end;
    }

    ec_key = EC_KEY_new_by_curve_name(nid);
    if( 1 != EC_KEY_set_public_key(ec_key,point))
    {
        goto end;
    }

    //获取EVP密钥结构
    key = EVP_PKEY_new(); 
    if( 1 != EVP_PKEY_set1_EC_KEY(key,ec_key) ){
        goto end;
    }

    ctx = EVP_PKEY_CTX_new(key, NULL); 

    if (EVP_PKEY_encrypt_init(ctx) <= 0){
        goto end;
    }

    size_t outlen;
    outlen = inHex.length()/2 + 128;
    out = (unsigned char*)OPENSSL_malloc(outlen);  
    unsigned char *poutsaved = out;

    bytein = QByteArray::fromHex(inHex.toUtf8());

    //加密结果有ANS1填充
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, (unsigned char*)bytein.data() , bytein.length() );
    if ( ret<= 0)
    {
        goto end;
    }

    d2i_SM2CiphertextValue(&asn1decode,(const unsigned char**)&out,outlen);
    OPENSSL_free(poutsaved);

    GMSSLST::SM2CiphertextValue_st * psm2 = (GMSSLST::SM2CiphertextValue_st*)asn1decode;

    bytetmp.append(  (char*)psm2->ciphertext->data, psm2->ciphertext->length);
    bytetmp.append( (char*)psm2->hash->data ,psm2->hash->length);

    outHex.append(BN_bn2hex( psm2->xCoordinate ));
    outHex.append(BN_bn2hex( psm2->yCoordinate ));
    outHex.append( bytetmp.toHex() );

end:
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(bnx);
    BN_free(bny);
    EC_KEY_free(ec_key);
    EVP_PKEY_CTX_free(ctx);
    SM2CiphertextValue_free(asn1decode);
    return ret;
}

int OPENSSL_API::sm2dec(QString d, QString in, QString &out)
{
    return 0;
}

int OPENSSL_API::sm3_hash(QString px, QString py, QString uid, QString data, QString &hash)
{
    if(px.isEmpty() || py.isEmpty() ||  uid.isEmpty() || data.isEmpty()   )
    {
        return 0;
    }

    int ret = -1;
    unsigned char digst[256] = {0};
    size_t digstlen =0;
    const EVP_MD   *md = EVP_sm3();

    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *bnx = NULL;
    BIGNUM *bny = NULL;

    QByteArray byteuid( QByteArray::fromHex(uid.toUtf8()));
    QByteArray bytedata( QByteArray::fromHex(data.toUtf8()));
    QByteArray byteHash;

     //获取ECC公钥结构
    int nid = NID_sm2p256v1;
    group = EC_GROUP_new_by_curve_name(nid);
    point = EC_POINT_new(group);
    bnx = BN_new();
    bny = BN_new();
    BN_hex2bn(&bnx, px.toStdString().c_str() );
    BN_hex2bn(&bny, py.toStdString().c_str() );

    if( 1 != EC_POINT_set_affine_coordinates_GFp(group,point,bnx,bny,NULL))
    {
        goto end;
    }

    ec_key = EC_KEY_new_by_curve_name(nid);
    if( 1 != EC_KEY_set_public_key(ec_key,point))
    {
        goto end;
    }

    //计算摘要
    memset(digst,0,sizeof(digst));
    digstlen = sizeof(digst);
    SM2_compute_message_digest(md,md
                               ,(unsigned char*)bytedata.data(),bytedata.length()
                               , byteuid.data(), byteuid.length()
                               , digst, &digstlen, ec_key);
    if(digstlen!=32)
        goto end;
    ret = 1;

    byteHash.append( (char*)digst, digstlen );
    hash = byteHash.toHex();

end:
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(bnx);
    BN_free(bny);
    EC_KEY_free(ec_key);
    return ret;
}

int OPENSSL_API::sm2sign(QString d,QString hash , QString &sign)
{
    if(d.isEmpty()  ||  hash.isEmpty())
    {
        return 0;
    }

    int ret = -1;
    char *psig = NULL;
    EC_KEY *ec_key = NULL;

    BIGNUM *bnd = BN_new();
    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;

    EVP_PKEY *key = NULL;
    ECDSA_SIG *sm2sig = ECDSA_SIG_new();


    unsigned char der_sig[256] = {0};
    int der_sig_len = 0;
    unsigned char digst[256] = {0};

    QByteArray bytehash( QByteArray::fromHex(hash.toUtf8()));

     //获取ECC密钥结构
    int nid = NID_sm2p256v1;
    ec_key = EC_KEY_new_by_curve_name(nid);
    if( 1 != EC_KEY_set_private_key(ec_key,bnd))
    {
        goto end;
    }


    //获取hash值
    memcpy( digst,  bytehash.data() , bytehash.length());

    //签名
    der_sig_len = sizeof(der_sig);
    if (!SM2_sign(NID_undef, digst, bytehash.length(), der_sig, (unsigned int *)&der_sig_len, ec_key))
    {
        goto end;
    }
    ret = 1;

    //获取签名值
    psig = (char*)der_sig;
    if (!(sm2sig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&psig, der_sig_len)))
    {
        goto end;
    }
    ECDSA_SIG_get0( sm2sig, &sig_r,  &sig_s);

    psig = BN_bn2hex((BIGNUM*)sig_r);
    sign.append(psig);
    OPENSSL_free(psig);
    psig = BN_bn2hex((BIGNUM*)sig_s);
    sign.append(psig);
    OPENSSL_free(psig);

end:
//    BN_free(bnd);
//    EC_KEY_free(ec_key);
//    ECDSA_SIG_free(sm2sig);

    return ret;
}

int OPENSSL_API::sm2verify(QString px ,QString py , QString hash  , QString sign)
{
    if(px.isEmpty() || py.isEmpty() ||  hash.isEmpty() || sign.isEmpty()   )
    {
        return 0;
    }

    int ret = -1;
    unsigned char digst[256] = {0};

    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *bnx = BN_new();
    BIGNUM *bny = BN_new();

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    ECDSA_SIG *sm2sig = ECDSA_SIG_new();
    BIGNUM *sig_r = BN_new();
    BIGNUM *sig_s = BN_new();
    unsigned char *der_sig = NULL;
    int der_sig_len = 0;

    QByteArray bytesign( QByteArray::fromHex(sign.toUtf8()));
    QByteArray bytehash( QByteArray::fromHex(hash.toUtf8()));



     //获取ECC公钥结构
    int nid = NID_sm2p256v1;
    group = EC_GROUP_new_by_curve_name(nid);
    point = EC_POINT_new(group);
    BN_hex2bn(&bnx, px.toStdString().c_str() );
    BN_hex2bn(&bny, py.toStdString().c_str() );

    if( 1 != EC_POINT_set_affine_coordinates_GFp(group,point,bnx,bny,NULL))
    {
        goto end;
    }

    ec_key = EC_KEY_new_by_curve_name(nid);
    if( 1 != EC_KEY_set_public_key(ec_key,point))
    {
        goto end;
    }


    //获取EVP密钥结构
    key = EVP_PKEY_new();
    if( 1 != EVP_PKEY_set1_EC_KEY(key,ec_key) ){
        goto end;
    }


    //获取hash值
    memcpy( digst,  bytehash.data() , bytehash.length());

    //获取签名值
    BN_bin2bn( (unsigned char*)bytesign.data(),bytesign.length()/2 ,sig_r );
    BN_bin2bn( (unsigned char*)bytesign.data()+bytesign.length()/2,bytesign.length()/2 ,sig_s );
    ECDSA_SIG_set0(sm2sig, sig_r, sig_s);
    der_sig_len = i2d_ECDSA_SIG(sm2sig,&der_sig);

    //开始验证
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (EVP_PKEY_verify_init(ctx) <= 0){
        goto end;
    }

    ret = EVP_PKEY_verify(ctx, der_sig, der_sig_len , digst , 32 );
    if ( ret<= 0)
    {
        goto end;
    }
    ret = 1;

end:
    OPENSSL_free(der_sig);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(bnx);
    BN_free(bny);
    BN_free(sig_r);
    BN_free(sig_s);
    EC_KEY_free(ec_key);
    EVP_PKEY_CTX_free(ctx);
    ECDSA_SIG_free(sm2sig);

    return ret;
}






