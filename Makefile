CC ?= gcc
CFLAGS ?= -Wall -Iinc/ -g

CFLAGS += $(shell pkg-config --cflags libcurl json-c openssl)
LDFLAGS += $(shell pkg-config --libs libcurl json-c openssl)

SRC := src/main.c \
	src/check.point.sucks.c

build:
	@mkdir -p out
	$(CC) $(CFLAGS) $(SRC) -o out/check.point.sucks $(LDFLAGS)

clean:
	@rm -rf out/
