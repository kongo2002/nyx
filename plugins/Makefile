INCLUDES := -I. -I.. -I../src
FLAGS    := -shared -fpic

all: test.so

%.so: %.o
	$(CC) $(FLAGS) -o $@ $<

%.o: %.c
	$(CC) $(INCLUDES) -fpic -c -o $@ $<
