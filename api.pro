#-------------------------------------------------
#
# Project created by QtCreator 2015-02-03T19:45:44
#
#-------------------------------------------------

QT       -= core gui

TARGET = binaryninjaapi
TEMPLATE = lib
CONFIG += staticlib

SOURCES += binaryninjaapi.cpp

HEADERS += binaryninjaapi.h
unix {
    target.path = /usr/lib
    INSTALLS += target
}

INCLUDEPATH += $$PWD/../core
DEPENDPATH += $$PWD/../core
