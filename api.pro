#-------------------------------------------------
#
# Project created by QtCreator 2015-02-03T19:45:44
#
#-------------------------------------------------

QT       -= core gui

TARGET = binaryninjaapi
TEMPLATE = lib
CONFIG += staticlib
CONFIG += c++11

SOURCES += \
    databuffer.cpp \
    filemetadata.cpp \
    fileaccessor.cpp \
    binaryview.cpp \
    binaryviewtype.cpp \
    binaryreader.cpp \
    binarywriter.cpp \
    transform.cpp \
	architecture.cpp \
	basicblock.cpp \
	function.cpp

HEADERS += binaryninjaapi.h
unix {
    target.path = /usr/lib
    INSTALLS += target
}

INCLUDEPATH += $$PWD/../core
DEPENDPATH += $$PWD/../core
