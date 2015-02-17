#-------------------------------------------------
#
# Project created by QtCreator 2015-02-03T19:45:44
#
#-------------------------------------------------

QT       -= core gui

TARGET = binaryninjaapi
TEMPLATE = lib
CONFIG += staticlib

SOURCES += \
    databuffer.cpp \
    filemetadata.cpp \
    fileaccessor.cpp \
    binaryview.cpp \
    binaryviewtype.cpp \
    binaryreader.cpp \
    binarywriter.cpp \
    transform.cpp \
	architecture.cpp

HEADERS += binaryninjaapi.h
unix {
    target.path = /usr/lib
    INSTALLS += target
}

INCLUDEPATH += $$PWD/../core
DEPENDPATH += $$PWD/../core

!win32 {
	QMAKE_CXXFLAGS += -std=c++11
}
