# Path to prebuilt libbinaryninjaapi.a
BINJA_API_A := ../../bin/libbinaryninjaapi.a

# Path to binaryninjaapi.h and json
INC := -I../../

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	# Path to binaryninja install
	BINJAPATH := $(HOME)/binaryninja
else
	BINJAPATH := /Applications/Binary\ Ninja.app/Contents/MacOS
endif

SRCDIR := src
BUILDDIR := build
TARGETDIR := bin

TARGETNAME := breakpoint
TARGET := $(TARGETDIR)/$(TARGETNAME)
INSTALLBINDIR := $(BINJAPATH)/plugins/

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

LIBS := -L $(BINJAPATH) -lbinaryninjacore
CFLAGS := -c -std=gnu++11 -O2 -Wall -W -fPIC -pipe
ifeq ($(UNAME_S),Linux)
	CC := g++
all: $(TARGET).so
else
	CC := $(shell xcrun -f clang++)
	CFLAGS += -arch x86_64 -pipe -stdlib=libc++ -mmacosx-version-min=10.7
all: $(TARGET).dylib
endif

$(TARGET).so: $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) -shared $^ $(BINJA_API_A) $(LIBS) -o $@

$(TARGET).dylib: $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) -dynamiclib $^ $(BINJA_API_A) $(LIBS) -o $@
	install_name_tool -id @loader_path/$(TARGETNAME).dylib -add_rpath @loader_path/.. $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	$(RM) -r $(BUILDDIR) $(TARGETDIR)

install:
	cp $(TARGET) $(INSTALLBINDIR)
	
.PHONY: clean
