CC       ?= gcc
CXXFLAGS := -Wall -Wextra -std=gnu89

INCLUDES := -I.
LIBS     := -lyaml -lpthread

SRCS     := $(wildcard src/*.c)
OBJECTS  := $(patsubst src/%.c,src/%.o, $(SRCS))
DEPS     := $(OBJECTS:.o=.d)

TSRCS    := $(wildcard tests/*.c)
TOBJECTS := $(patsubst tests/%.c,tests/%.o, $(TSRCS))
TLIBS    := -lcmocka
TDEPS    := $(filter-out src/main.o, $(OBJECTS))

# install directories

PREFIX     ?= /usr/local
MANPREFIX  ?= $(PREFIX)/share/man
DOCDIR     ?= $(PREFIX)/share/doc

INSTALLDIR := $(DESTDIR)$(PREFIX)
MANPREFIX  := $(DESTDIR)$(MANPREFIX)
DOCDIR     := $(DESTDIR)$(DOCDIR)

DEBUG ?= 1
ifeq ($(DEBUG), 1)
    CXXFLAGS+= -O0 -ggdb
else
    CXXFLAGS+= -O2 -DNDEBUG
endif

.PHONY: all clean rebuild check install uninstall

all: nyx

-include $(DEPS)

nyx: $(OBJECTS)
	$(CC) $(OBJECTS) -o nyx $(LIBS)

check: test
	@./test

test: $(TOBJECTS) $(TDEPS)
	$(CC) $(TOBJECTS) $(TDEPS) -o test $(LIBS) $(TLIBS)

tests/%.o: tests/%.c
	$(CC) -c $(CXXFLAGS) $(INCLUDES) -o $@ $<

src/%.o: src/%.c
	$(CC) -c $(CXXFLAGS) $(INCLUDES) -MMD -MF $(patsubst %.o,%.d,$@) -o $@ $<

tags: $(SRCS)
	ctags -R --c-kinds=+lp --fields=+iaS --extra=+q --language-force=C .

install: nyx
	install -d $(INSTALLDIR)/bin
	install nyx $(INSTALLDIR)/bin/nyx
	install -d $(DOCDIR)/nyx
	install -m644 README.markdown LICENSE $(DOCDIR)/nyx

uninstall:
	rm -rf $(INSTALLDIR)/bin/nyx
	rm -rf $(DOCDIR)/nyx

clean:
	@rm -rf src/*.o
	@rm -rf src/*.d
	@rm -rf tests/*.o
	@rm -f nyx
	@rm -f test

rebuild: clean all
