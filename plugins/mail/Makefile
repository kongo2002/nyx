INCLUDES := -I. -I../../src
FLAGS    := -shared -fpic

all: mail.so

%.so: %.o
	$(CC) $(FLAGS) -lcurl -o $@ $<

%.o: %.c
	$(CC) $(INCLUDES) -Wall -Wextra -fpic -c -o $@ $<
