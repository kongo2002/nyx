CC       ?= gcc
CXXFLAGS := -std=c99 -pedantic -Wall -Wextra

INCLUDES := -I.
LIBS     := -lyaml -lpthread

# DEBUG/RELEASE BUILD

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CXXFLAGS+= -O0 -g -Werror -Wshadow
    BUILD=DEBUG
else
    CXXFLAGS+= -O2 -DNDEBUG -Wno-unused-parameter
    BUILD=RELEASE
endif

# FILES

SRCS     := $(wildcard src/*.c)
OBJECTS  := $(patsubst src/%.c,src/%.o, $(SRCS))
DEPS     := $(OBJECTS:.o=.d)

TSRCS    := $(wildcard tests/*.c)
TOBJECTS := $(patsubst tests/%.c,tests/%.o, $(TSRCS))
TLIBS    := -lcmocka
TDEPS    := $(filter-out src/main.o, $(OBJECTS))

# LOOK FOR LOCALLY CMOCKA SOURCES

CMOCKA_HEADER="$(shell find . -name cmocka.h)"
ifneq ($(CMOCKA_HEADER), "")
    CMOCKA_LIB="$(shell find . -name libcmocka.so | grep -v obj32)"

    TINCLUDES+= -I"$(shell dirname $(CMOCKA_HEADER))"
    TLIBS+= -L"$(shell dirname $(CMOCKA_LIB))"
endif

# OS SPECIFICS

ifeq ($(shell uname -s), Darwin)
    CXXFLAGS+= -DOSX
    OBJECTS := $(filter-out src/event.o, $(OBJECTS))
    TDEPS   := $(filter-out src/event.o, $(TDEPS))

    IS_OSX := yes
else
    IS_OSX := no
endif

# PLUGINS

PLUGINS ?= 0
ifeq ($(PLUGINS), 1)
    LIBS+= -ldl -rdynamic
    CXXFLAGS+= -DUSE_PLUGINS
    HAS_PLUGINS := yes
else
    OBJECTS := $(filter-out src/plugins.o, $(OBJECTS))
    TDEPS   := $(filter-out src/plugins.o, $(TDEPS))
    HAS_PLUGINS := no
endif

# SSL

SSL ?= 0
ifeq ($(SSL), 1)
    LIBS+= -lssl -lcrypto
    CXXFLAGS+= -DUSE_SSL
    HAS_SSL := yes
else
    OBJECTS := $(filter-out src/ssl.o, $(OBJECTS))
    TDEPS   := $(filter-out src/ssl.o, $(TDEPS))
    HAS_SSL := no
endif

# TRY TO DETERMINE GIT VERSION

GITVERSION ?= $(shell ./utils/git-version.sh)
CXXFLAGS   += $(GITVERSION)

# INSTALL DIRECTORIES

PREFIX     ?= /usr/local
MANPREFIX  ?= $(PREFIX)/share/man
DOCDIR     ?= $(PREFIX)/share/doc

INSTALLDIR := $(DESTDIR)$(PREFIX)
MANPREFIX  := $(DESTDIR)$(MANPREFIX)
DOCDIR     := $(DESTDIR)$(DOCDIR)

.PHONY: all options clean rebuild check install uninstall

all: options nyx nyx.1.gz

-include $(DEPS)

options:
	@echo nyx build options
	@echo "build      : $(BUILD)"
	@echo "CC         : $(CC)"
	@echo "PLUGINS    : $(HAS_PLUGINS)"
	@echo "SSL        : $(HAS_SSL)"
	@echo "OSX        : $(IS_OSX)"
	@echo "CXXFLAGS   : $(CXXFLAGS)"
	@echo "INSTALLDIR : $(INSTALLDIR)"
	@echo "MANPREFIX  : $(MANPREFIX)"
	@echo "DOCDIR     : $(DOCDIR)"
	@echo

nyx: $(OBJECTS)
	$(CC) $(OBJECTS) -o nyx $(LIBS)

check: test
ifneq ("$(CMOCKA_LIB)", "")
	@LD_LIBRARY_PATH=$(shell dirname $(CMOCKA_LIB)) ./test
else
	@./test
endif

run-tests: nyx
	@./tests/scripts/run-tests.sh
	@./tests/scripts/run-configs.sh

test: $(TOBJECTS) $(TDEPS)
	$(CC) $(TOBJECTS) $(TDEPS) -o test $(LIBS) $(TLIBS)

tests/%.o: tests/%.c
	$(CC) -c $(CXXFLAGS) $(INCLUDES) $(TINCLUDES) -o $@ $<

src/%.o: src/%.c
	$(CC) -c $(CXXFLAGS) $(INCLUDES) -MMD -MF $(patsubst %.o,%.d,$@) -o $@ $<

nyx.1.gz: nyx.1
	@gzip -c $< > $@

tags: $(SRCS)
	ctags -R --c-kinds=+lp --fields=+iaS --extra=+q --language-force=C .

install: all
	install -d $(INSTALLDIR)/bin
	install nyx $(INSTALLDIR)/bin/nyx
	install -d $(DOCDIR)/nyx
	install -m644 README.markdown LICENSE $(DOCDIR)/nyx
	install -d $(MANPREFIX)/man1
	install -m644 nyx.1.gz $(MANPREFIX)/man1/

uninstall:
	rm -f $(INSTALLDIR)/bin/nyx
	rm -f $(MANPREFIX)/man1/nyx.1.gz
	rm -rf $(DOCDIR)/nyx

clean:
	@rm -rf src/*.o
	@rm -rf src/*.d
	@rm -rf tests/*.o
	@rm -f nyx
	@rm -f test
	@rm -f nyx.1.gz

rebuild: clean all
