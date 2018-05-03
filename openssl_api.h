#ifndef OPENSSL_API_H
#define OPENSSL_API_H
#include <QString>

#define  DES 1<<0  //b 00000000 00000001  //16bits
#define  AES 1<<1  //b 00000000 00000010
#define  SM4 1<<2  //b 00000000 00000100

#define  ECB 1<<16  //b 00000001 00000000 00000000
#define  CBC 1<<17 //b 00000010 00000000 00000000
#define  CFB 1<<18 //b 00000010 00000000 00000000
#define  OFB 1<<19 //b 00000010 00000000 00000000


class OPENSSL_API
{
public:
    OPENSSL_API();

    static int enc(QString keyHex, QString ivHex, int alg, int mode, QString inHex, QString& outHex);
    static int dec(QString keyHex, QString ivHex, int alg , int mode ,QString inHex , QString& outHex);

    static int genrsa(QString bits, QString e, QString& outPKDer, QString& outVKDer );
    static int rsa_pkenc(QString derpk, QString in, int padding,  QString& out);
    static int rsa_vkdec(QString dervk, QString in, int padding,  QString& out);
    static int rsa_vkenc(QString dervk, QString in, int padding,  QString& out);
    static int rsa_pkdec(QString derpk, QString in, int padding,  QString& out);

    /*
    alg 1:md5 2:sm3 3:ISO10118-2 4:sha1 5:sha224 6:sha256 7:sha384 8:sha512
    */
    static int hash(QString inHex, int alg, QString& out);

    static int gensm2(QString& x, QString& y, QString& d);
    static int sm2enc(QString px ,QString py  , QString in , QString& out);

    //私钥解密失败 私钥签名返回成功 但结果错误
    static int sm2dec(QString d ,QString in   , QString& out);

    static int sm3_hash(QString px, QString py, QString uid, QString data, QString &hash);
    static int sm2sign(QString d,QString hash , QString &sign);
    static int sm2verify(QString px ,QString py , QString hash  , QString sign);
};

#endif // OPENSSL_API_H
