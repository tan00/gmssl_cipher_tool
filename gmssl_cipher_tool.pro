#-------------------------------------------------
#
# Project created by QtCreator 2018-01-30T17:31:04
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = gmssl_cipher_tool
TEMPLATE = app

RC_FILE += gmssl_cipher_tool.rc

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    openssl_api.cpp

HEADERS += \
        mainwindow.h \
    openssl_api.h \
    myhelper.h

FORMS += \
        mainwindow.ui


INCLUDEPATH += $$PWD/include
DEPENDPATH += $$PWD/include

unix:!macx: LIBS += -L$$PWD/lib -lcrypto
win32: LIBS += -L$$PWD/lib/     -llibcrypto

#win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../../../App/Develop/gmssl/lib/libcrypto.lib
#else:win32-g++: PRE_TARGETDEPS += $$PWD/../../../App/Develop/gmssl/lib/libcrypto.a
