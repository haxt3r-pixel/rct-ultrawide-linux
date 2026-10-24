CC ?= cc
STRIP ?= strip
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wstrict-prototypes -Wmissing-prototypes -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS ?= -static-pie
SOURCE := src/rct-ultrawide.c
OUTPUT := build/rct-ultrawide
RELEASE_OUTPUT := build/rct-ultrawide-linux-x86_64
TEST_OUTPUT := build/test-rct-ultrawide

.PHONY: all release test clean

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SOURCE) $(LDFLAGS) -o $(OUTPUT)

release: $(SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SOURCE) $(LDFLAGS) -o $(RELEASE_OUTPUT)
	$(STRIP) --strip-all $(RELEASE_OUTPUT)
	cd build && sha256sum rct-ultrawide-linux-x86_64 > rct-ultrawide-linux-x86_64.sha256

test: $(TEST_OUTPUT)
	$(TEST_OUTPUT)

$(TEST_OUTPUT): tests/test_rct_ultrawide.c $(SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) tests/test_rct_ultrawide.c $(LDFLAGS) -o $(TEST_OUTPUT)

clean:
	rm -rf build
