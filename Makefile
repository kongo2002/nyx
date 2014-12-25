CXX      := gcc
CXXFLAGS := -O2 -Wall

INCLUDES := -I.
LIBS     := -lyaml

SRCS     := $(wildcard *.c)
OBJECTS  := $(patsubst %.c,%.o,$(SRCS))
DEPS     := $(OBJECTS:.o=.d)

all: nyx

-include $(DEPS)

nyx: $(OBJECTS)
	$(CXX) $(OBJECTS) -o nyx $(LIBS)

%.o: %.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -MMD -MF $(patsubst %.o,%.d,$@) -o $@ $<

run: nyx
	./nyx config.yaml

tags: $(SRCS)
	ctags -R --c-kinds=+lp --fields=+iaS --extra=+q --language-force=C .

clean:
	@rm -rf *.o
	@rm -rf *.d
	@rm -f nyx

rebuild: clean all

.PHONY: all clean run rebuild
