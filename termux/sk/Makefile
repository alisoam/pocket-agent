GO     = go
TARGET = libpocket-sk.so

.PHONY: all clean help

all: $(TARGET)

$(TARGET): bridge.go backend.go
	@echo "Building PocketSSH SK provider (Termux)..."
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared -o $(TARGET) .
	@echo "Built: $(TARGET)"
	@ls -lh $(TARGET)

clean:
	rm -f $(TARGET) libpocket-sk.h

help:
	@echo "PocketSSH SecurityKey Provider (Termux)"
	@echo ""
	@echo "Build in Termux:  pkg install golang && make"
	@echo ""
	@echo "Usage:"
	@echo "  ssh-keygen -t ed25519-sk -D ./$(TARGET)"
	@echo "  ssh -o SecurityKeyProvider=./$(TARGET) user@host"
	@echo ""
	@echo "The .so automatically spawns a bridge process via app_process"
	@echo "that communicates with PocketSSHAgent over Binder/AIDL."
	@echo "No manual setup required — just build and use."
