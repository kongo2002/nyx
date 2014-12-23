CXX      := gcc
CXXFLAGS := -O2 -Wall

INCLUDES := -I.
LIBS     := -lyaml

OBJECTS  := config.o list.o main.o
DEPS     := $(OBJECTS:.o=.d)

-include $(DEPS)

all: nyx

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
