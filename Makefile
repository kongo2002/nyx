CXX      := gcc
CXXFLAGS := -Wall -std=gnu89

INCLUDES := -I.
LIBS     := -lyaml -lpthread

VPATH    := src

SRCS     := $(wildcard src/*.c)
OBJECTS  := $(patsubst src/%.c,src/%.o,$(SRCS))
DEPS     := $(OBJECTS:.o=.d)

DEBUG ?= 1
ifeq ($(DEBUG), 1)
    CXXFLAGS+= -O0 -ggdb
else
    CXXFLAGS+= -O2 -DNDEBUG
endif

all: nyx

-include $(DEPS)

nyx: $(OBJECTS)
	$(CXX) $(OBJECTS) -o nyx $(LIBS)

src/%.o: %.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -MMD -MF $(patsubst %.o,%.d,$@) -o $@ $<

run: nyx
	./nyx config.yaml

tags: $(SRCS)
	ctags -R --c-kinds=+lp --fields=+iaS --extra=+q --language-force=C .

clean:
	@rm -rf src/*.o
	@rm -rf src/*.d
	@rm -f nyx

rebuild: clean all

.PHONY: all clean run rebuild
