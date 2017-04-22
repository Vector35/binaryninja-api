#UNAME_S := $(shell uname -s)
#ifeq ($(UNAME_S),Darwin)
#	LIB := -L/Applications/Binary\ Ninja.app/Contents/MacOS/ -lbinaryninjacore
#else
#	LIB := -L$(HOME)/binaryninja/ -lbinaryninjacore
#endif


TARGETDIR := bin
TARGETNAME := libbinaryninjaapi
TARGET := $(TARGETDIR)/$(TARGETNAME)

SRCEXT = .cpp
SOURCES = $(wildcard *$(SRCEXT))
OBJECTS = $(SOURCES:.cpp=.o) json.o


CFLAGS := -c -fPIC -O2 -pipe -std=gnu++11 -Wall -W
ifeq ($(UNAME_S),Darwin)
	CC := $(shell xcrun -f g++)
	AR := $(shell xcrun -f ar)
	CFLAGS += -stdlib=libc++
else
	CC := g++
	AR := ar
endif

all: $(TARGET).a

$(TARGET).a: $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(AR) rcs $@ $^
 
%.o: %.cpp
	@echo " Compiling... $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

json.o: ./json/jsoncpp.cpp ./json/json.h ./json/json-forwards.h
	$(CC) $(CFLAGS) -I. -c -o $@ $<

clean:
	@echo " Cleaning...";
	$(RM) -r *.o $(TARGETDIR)

.PHONY: clean
