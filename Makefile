#UNAME_S := $(shell uname -s)
#ifeq ($(UNAME_S),Darwin)
#	LIB := -L/Applications/Binary\ Ninja.app/Contents/MacOS/ -lbinaryninjacore
#else
#	LIB := -L$(HOME)/binaryninja/ -lbinaryninjacore
#endif

INSTALLPATH := ~/binaryninja

TARGETDIR := bin
TARGETNAME := libbinaryninjaapi
TARGET := $(TARGETDIR)/$(TARGETNAME)

SRCEXT = .cpp
SOURCES = $(wildcard *$(SRCEXT))
OBJECTS = $(SOURCES:.cpp=.o) json.o


CFLAGS := -c -fPIC -O2 -pipe -std=gnu++11 -Wall -W -Wextra -Wshadow
CPPFLAGS := -O2 -std=c++11 -Wall -W -Wextra -Wshadow
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

install: generate $(TARGET).a
	@echo "Installing binaryninja API.";
	cp -r python/* $(INSTALLPATH)/python/binaryninja
	cp $(TARGET).a $(INSTALLPATH)
	@echo "Done.";

generator: python/generator.cpp $(TARGET).a
	@echo "Building generator...";
	$(CC) $(CPPFLAGS) -I . $< -L$(TARGETDIR) -lbinaryninjaapi -L $(INSTALLPATH) -lbinaryninjacore -o $@
	chmod +x $@

generate: generator
	@echo "Running generator...";
	LD_LIBRARY_PATH=$(INSTALLPATH) ./generator binaryninjacore.h python/_binaryninjacore.py python/enums.py

python/_binaryninjacore.py: generate

python/enums.py: generate

python_test: environment python/_binaryninjacore.py python/enums.py
	python2 suite/unit.py
	python3 suite/unit.py

oracle: environment python/_binaryninjacore.py python/enums.py
	python3 suite/generator.py

environment: environment_clean python/_binaryninjacore.py python/enums.py 
	@echo "Copying over libs..."
	cp $(INSTALLPATH)/libbinaryninjacore.so.1 .
	cp $(INSTALLPATH)/libbinaryninjacore.so.1 python/

	@echo "Building 'binaryninja' Packages..."
	mkdir -p suite/binaryninja/
	cp -r python/* suite/binaryninja/
	cp -r suite/binaryninja/ python/examples/

	@echo "Copying Architectures Over..."
	cp -r $(INSTALLPATH)/types/ .
	cp -r $(INSTALLPATH)/plugins/ .
	cp -r $(INSTALLPATH)/types/ python/
	cp -r $(INSTALLPATH)/plugins/ python/

environment_clean:
	@echo "Removing 'binaryninja' Packages..."
	rm -rf suite/binaryninja/
	rm -rf python/examples/binaryninja/
	
	@echo "Removing libs..."
	rm -f libbinaryninjacore.so.1
	rm -f python/libbinaryninjacore.so.1

	@echo "Removing Architectures..."
	rm -rf types/
	rm -rf plugins/
	rm -rf python/types/
	rm -rf python/plugins/

clean: 
	@echo " Cleaning...";
	$(RM) -r *.o $(TARGETDIR) generator

squeaky: clean environment_clean

.PHONY: clean environment_clean squeaky python/_binaryninjacore.py python/enums.py
