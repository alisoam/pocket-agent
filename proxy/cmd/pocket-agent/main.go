package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/example/pocket-agent-proxy/internal/agent"
	"github.com/example/pocket-agent-proxy/internal/ble"
	"github.com/example/pocket-agent-proxy/internal/pairing"
)

func main() {
	// Subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "pair":
		cmdPair(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`pocket-agent - SSH agent proxy over BLE

Usage:
  pocket-agent pair   Generate pairing QR code for the phone app
  pocket-agent run    Start the SSH agent proxy (connect via BLE)
  pocket-agent help   Show this help message

Environment:
  SSH_AUTH_SOCK is set to the agent socket path when running.`)
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

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "Path for the SSH agent socket")
	configDir := fs.String("config", defaultConfigDir(), "Configuration directory")
	fs.Parse(args)

	// Load device keys for authentication
	keys, err := pairing.LoadOrGenerateKeys(filepath.Join(*configDir, "keys"))
	if err != nil {
		log.Fatalf("Failed to load keys: %v", err)
	}

	// Connect to phone via BLE
	bleClient := ble.NewClient()
	if err := bleClient.Connect(); err != nil {
		log.Fatalf("BLE connection failed: %v", err)
	}
	defer bleClient.Disconnect()

	// Authenticate with the phone
	if err := bleClient.Authenticate(keys.PrivateKey); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Start SSH agent socket server
	server := agent.NewServer(*socketPath, bleClient)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start agent server: %v", err)
	}
	defer server.Stop()

	fmt.Printf("\nexport SSH_AUTH_SOCK=%s\n\n", *socketPath)
	fmt.Println("SSH agent proxy is running. Press Ctrl+C to stop.")

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
}

func defaultConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "pocket-agent")
}

func defaultSocketPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("pocket-agent-%d.sock", os.Getuid()))
}

func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "Linux Desktop"
	}
	return name
}
