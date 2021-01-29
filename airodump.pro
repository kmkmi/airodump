TEMPLATE = app
QMAKE_CXXFLAGS += -std=c++11
CONFIG += console
CONFIG += c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp

HEADERS += \
    main.h
