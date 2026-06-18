package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/example/pocket-agent-desktop/internal/ble"
	"github.com/example/pocket-agent-desktop/internal/pairing"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "pair":
		cmdPair(os.Args[2:])
	case "test":
		cmdTest(os.Args[2:])
	case "verify-attestation":
		cmdVerifyAttestation(os.Args[2:])
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`pocket-agent - PocketSSH SK provider companion

Usage:
  pocket-agent pair                Generate pairing QR code for the phone app
  pocket-agent test                Connect to phone and verify BLE + authentication
  pocket-agent verify-attestation  Verify a hardware-attestation file written by ssh-keygen
  pocket-agent help                Show this help message

After pairing, use the SK provider directly:
  ssh-keygen -t ed25519-sk -w /path/to/libpocket-sk.so
  ssh-keygen -t ecdsa-sk   -w /path/to/libpocket-sk.so -O write-attestation=key.attest
  pocket-agent verify-attestation key.attest`)
}

func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	configDir := fs.String("config", defaultConfigDir(), "Configuration directory")
	fs.Parse(args)

	keys, err := pairing.LoadOrGenerateKeys(filepath.Join(*configDir, "keys"))
	if err != nil {
		log.Fatalf("[1/3] Failed to load keys: %v", err)
	}
	fmt.Println("[1/3] Device keys loaded")

	client := ble.NewClient()
	if err := client.Connect(); err != nil {
		log.Fatalf("[2/3] BLE connection failed: %v", err)
	}
	defer client.Disconnect()
	fmt.Println("[2/3] BLE connected")

	if err := client.Authenticate(keys.PrivateKey); err != nil {
		log.Fatalf("[3/3] Authentication failed: %v", err)
	}
	fmt.Println("[3/3] Authenticated (AES-256-GCM session established)")
	fmt.Println("\nAll tests passed! SK provider can communicate with phone.")
}

func cmdPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	label := fs.String("label", getHostname(), "Device label shown on phone")
	configDir := fs.String("config", defaultConfigDir(), "Configuration directory")
	output := fs.String("output", "", "Save QR code as PNG to this path")
	fs.Parse(args)

	keys, err := pairing.LoadOrGenerateKeys(filepath.Join(*configDir, "keys"))
	if err != nil {
		log.Fatalf("Failed to load/generate keys: %v", err)
	}

	if err := pairing.GenerateQR(keys, *label, *output); err != nil {
		log.Fatalf("Failed to generate QR: %v", err)
	}
}

func defaultConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "pocket-agent")
}

func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "Linux Desktop"
	}
	return name
}
