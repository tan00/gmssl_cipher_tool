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

};

#endif // OPENSSL_API_H
