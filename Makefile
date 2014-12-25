CXX      := gcc
CXXFLAGS := -O2 -Wall

INCLUDES := -I.
LIBS     := -lyaml

OBJECTS  := $(patsubst %.c,%.o,$(wildcard *.c))
DEPS     := $(OBJECTS:.o=.d)

all: nyx

-include $(DEPS)

nyx: $(OBJECTS)
	$(CXX) $(OBJECTS) -o nyx $(LIBS)

%.o: %.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -MMD -MF $(patsubst %.o,%.d,$@) -o $@ $<

run: nyx
	./nyx config.yaml

clean:
	@rm -rf *.o
	@rm -rf *.d
	@rm -f nyx

rebuild: clean all

.PHONY: all clean run rebuild
