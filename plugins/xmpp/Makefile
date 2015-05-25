INCLUDES := -I. -I../../src
FLAGS    := -shared -fpic

all: xmpp.so

%.so: %.o
	$(CC) $(FLAGS) -lstrophe -lpthread -o $@ $<

%.o: %.c
	$(CC) $(INCLUDES) -Wall -Wextra -fpic -c -o $@ $<
