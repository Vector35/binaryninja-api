UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIB := -L/Applications/Binary\ Ninja.app/Contents/MacOS/ -lbinaryninjacore
else
	LIB := -L$(HOME)/binaryninja/ -lbinaryninjacore
endif


TARGETDIR := bin
TARGETNAME := libbinaryninjaapi
TARGET := $(TARGETDIR)/$(TARGETNAME)

SRCEXT = .cpp
SOURCES = $(wildcard *$(SRCEXT))
OBJECTS = $(SOURCES:.cpp=.o)


CFLAGS := -c -fPIC -O2 -pipe -std=gnu++11 -Wall -W
ifeq ($(UNAME_S),Darwin)
	CC := $(shell xcrun -f clang++)
	AR := $(shell xcrun -f ar)
	CFLAGS += -stdlib=libc++
all: $(TARGET).a $(TARGET).dylib
else
	CC := g++
	AR := ar
all: $(TARGET).a $(TARGET).so
endif

$(TARGET).a: $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(AR) rcs $@ $^
 
$(TARGET).so: $(OBJECTS)
	@mkdir -p $(TARGETDIR)
	$(CC) -shared $(LIB) $(JSONCPP) $^ -o $@

$(TARGET).dylib: $(OBJECTS)
	$(CC) -dynamiclib $(LIB) $(JSONCPP) $^ -o $@
	install_name_tool -id @loader_path/$(TARGETNAME).dylib -add_rpath @loader_path/.. $@

%.o: %.cpp
	@echo " Compiling... $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	@echo " Cleaning...";
	$(RM) -r *.o $(TARGETDIR)

.PHONY: clean
