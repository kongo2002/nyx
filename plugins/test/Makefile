INCLUDES := -I. -I../../src
FLAGS    := -shared -fpic

all: test.so

%.so: %.o
	$(CC) $(FLAGS) -o $@ $<

%.o: %.c
	$(CC) $(INCLUDES) -Wall -Wextra -fpic -c -o $@ $<
