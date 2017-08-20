# Path to prebuilt libbinaryninjaapi.a
BINJA_API_A := ../../bin/libbinaryninjaapi.a

# Path to binaryninjaapi.h and json
INC := -I../../

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	# Path to binaryninja install
	BINJAPATH := $(shell cat ~/.binaryninja/lastrun)
	PLUGIN_DIR := ~/.binaryninja/plugins/
	CC := g++
else
	BINJAPATH := /Applications/Binary\ Ninja.app/Contents/MacOS
	PLUGIN_DIR := ~/Library/Application\ Support/Binary\ Ninja/plugins/
	CC := clang++
endif

SRCDIR := src
BUILDDIR := build
TARGETDIR := bin

TARGETNAME := x86_extension
TARGET := $(TARGETDIR)/$(TARGETNAME)

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o)) src/asmx86/libasmx86.a

LIBS := -L$(BINJAPATH) -lbinaryninjacore
CFLAGS := -c -std=gnu++11 -O2 -Wall -W -fPIC -pipe

all: $(TARGET)

ifeq ($(UNAME_S),Linux)
$(TARGET): $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) $^ $(BINJA_API_A) $(LIBS) -shared -Wl,-rpath=$(BINJAPATH) -ldl -o bin/lib$(TARGETNAME).so
else
$(TARGET): $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) $^ $(BINJA_API_A) $(LIBS) -single_module -dynamiclib -o bin/lib$(TARGETNAME).dylib
	install_name_tool -add_rpath $(BINJAPATH)/libbinaryninjacore.dylib bin/lib$(TARGETNAME).dylib
endif

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

src/asmx86/libasmx86.a:
	$(MAKE) -C src/asmx86

install:
	cp bin/lib$(TARGETNAME).dylib $(PLUGIN_DIR)

clean:
	$(RM) -r $(BUILDDIR) $(TARGETDIR)

.PHONY: clean
