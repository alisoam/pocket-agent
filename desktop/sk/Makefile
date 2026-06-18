GO     = go
TARGET = libpocket-sk.so

.PHONY: all clean install help

all: $(TARGET)

# Build as a c-shared library: Go exports sk_* symbols directly,
# no separate C wrapper needed.
$(TARGET): bridge.go backend.go sk-api.h
	@echo "Building PocketSSH SK provider..."
	cd .. && CGO_ENABLED=1 $(GO) build -buildmode=c-shared -o sk/$(TARGET) ./sk/
	@echo "Built: $(TARGET)"
	@ls -lh $(TARGET)

clean:
	rm -f $(TARGET) libpocket-sk.h

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/lib/$(TARGET)
	@echo "Installed to /usr/local/lib/$(TARGET)"
	@echo ""
	@echo "Generate a phone-backed SSH key:"
	@echo "  ssh-keygen -t ed25519-sk -D /usr/local/lib/$(TARGET)"
	@echo ""
	@echo "Or set SecurityKeyProvider in ~/.ssh/config:"
	@echo "  SecurityKeyProvider /usr/local/lib/$(TARGET)"

help:
	@echo "PocketSSH SecurityKey Provider"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build $(TARGET)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/lib/"
	@echo "  help     - This message"
	@echo ""
	@echo "Usage (pocket-agent run must be running):"
	@echo "  ssh-keygen -t ed25519-sk -D ./$(TARGET)"
	@echo "  ssh -i ~/.ssh/id_ed25519_sk user@host"
