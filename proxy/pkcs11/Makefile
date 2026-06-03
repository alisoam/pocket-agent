# Makefile for PocketSSHAgent PKCS#11 Provider

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g
LDFLAGS = -shared

GO = go
GOBUILDMODE = c-archive
GOFLAGS = -buildmode=$(GOBUILDMODE)

TARGET = libpocket-pkcs11.so
GOLIB = libbridge.a
GOHEADER = libbridge.h

SOURCES = provider.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean test

all: $(TARGET)

# Build Go bridge as static library
$(GOLIB): bridge.go
	@echo "Building Go bridge library..."
	cd .. && $(GO) build $(GOFLAGS) -o pkcs11/$(GOLIB) ./pkcs11/bridge.go
	@echo "Go bridge built successfully"

# Compile C provider
provider.o: provider.c $(GOLIB)
	@echo "Compiling C provider..."
	$(CC) $(CFLAGS) -c provider.c -o provider.o
	@echo "C provider compiled"

# Link shared library
$(TARGET): $(OBJECTS) $(GOLIB)
	@echo "Linking PKCS#11 shared library..."
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(GOLIB) -lpthread -ldl
	@echo "Build complete: $(TARGET)"
	@ls -lh $(TARGET)

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET) $(OBJECTS) $(GOLIB) $(GOHEADER)
	@echo "Clean complete"

test: $(TARGET)
	@echo "Testing PKCS#11 provider..."
	@echo ""
	@echo "1. List slots:"
	@pkcs11-tool --module ./$(TARGET) --list-slots || echo "pkcs11-tool not installed"
	@echo ""
	@echo "2. List objects:"
	@pkcs11-tool --module ./$(TARGET) --list-objects || echo "Ensure Android app is running and paired"
	@echo ""
	@echo "Run 'make test-ssh' to test with SSH"

test-ssh:
	@echo "Testing with SSH (requires test server)..."
	@echo "ssh -I ./$(TARGET) -o PKCS11Provider=./$(TARGET) user@testserver"

help:
	@echo "PocketSSHAgent PKCS#11 Provider Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the PKCS#11 provider (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Test provider with pkcs11-tool"
	@echo "  test-ssh   - Show SSH testing command"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make           # Build libpocket-pkcs11.so"
	@echo "  make test      # Test with pkcs11-tool"
	@echo ""
	@echo "SSH Configuration:"
	@echo "  Add to ~/.ssh/config:"
	@echo "    Host myserver"
	@echo "      PKCS11Provider $(PWD)/$(TARGET)"
