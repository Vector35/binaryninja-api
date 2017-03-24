# Path to prebuilt libbinaryninjaapi.a
BINJA_API_A := ../../bin/libbinaryninjaapi.a

# Path to binaryninjaapi.h and json
INC := -I../../

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	# Path to binaryninja install
	BINJAPATH := $(HOME)/binaryninja/
	CC := g++
else
	BINJAPATH := /Applications/Binary\ Ninja.app/Contents/MacOS
	CC := $(shell xcrun -f clang++)
endif

SRCDIR := src
BUILDDIR := build
TARGETDIR := bin

TARGETNAME := print_syscalls
TARGET := $(TARGETDIR)/$(TARGETNAME)

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

LIBS := -L $(BINJAPATH) -lbinaryninjacore
CFLAGS := -c -std=gnu++11 -O2 -Wall -W -fPIC -pipe -ggdb
ifeq ($(UNAME_S),Darwin)
	CFLAGS += -arch x86_64 -pipe -stdlib=libc++
endif

all: $(TARGET)

ifeq ($(UNAME_S),Linux)
$(TARGET): $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) $^ $(BINJA_API_A) $(LIBS) -Wl,-rpath=$(BINJAPATH) -ldl -o $@
else
$(TARGET): $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) $^ $(BINJA_API_A) $(LIBS) -o $@
	install_name_tool -change @rpath/libbinaryninjacore.dylib $(BINJAPATH)/libbinaryninjacore.dylib $@
endif

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	$(RM) -r $(BUILDDIR) $(TARGETDIR)

.PHONY: clean
