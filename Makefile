TARGET=		libnss_tacplus.so.2
TEST_TARGET=	bin/dlharness
LIBS=		-lnsl -lpthread -ltac
TEST_LIBS=	-ldl

CC = gcc
CFLAGS =  -D_FORTIFY_SOURCE=2 -fstack-protector -std=gnu99 -Werror -Wall
CFLAGS += -ggdb -fPIC
LDFLAGS = -shared -Wl,-soname,libnss_tacplus.so.2


OBJECTS=$(patsubst %.c, %.o, $(wildcard src/*.c))
HEADERS=$(wildcard src/*.h)

TEST_OBJECTS=	$(patsubst %.c, %.o, $(wildcard test/*.c))
TEST_HEADERS=	$(wildcard test/*.h)

default: $(TARGET)
all: default
test: $(TEST_TARGET)

.PHONY: default all test clean

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

.PRECIOUS: $(TARGET) $(TEST_TARGET) (OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LIBS) $(LDFLAGS) -o $@

install:
	install -D $(TARGET) $(DESTDIR)/lib/x86_64-linux-gnu/$(TARGET) 

$(TEST_TARGET): $(TEST_OBJECTS)
	-mkdir -p bin
	$(CC) $(TEST_OBJECTS) $(TEST_LIBS) $(TEST_LDFLAGS) -o $@

clean:
	-rm -f src/*.o test/*.o
	-rm -f $(TARGET) $(TEST_TARGET)

