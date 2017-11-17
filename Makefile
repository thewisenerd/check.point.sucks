CC ?= gcc
CFLAGS ?= -Wall -Iinc/ -g

CFLAGS += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs json-c openssl)

LDFLAGS += -lcurl

default:
	$(CC) $(CFLAGS) src/check.point.sucks.c -o out/check.point.sucks $(LDFLAGS)
