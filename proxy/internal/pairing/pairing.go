package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/skip2/go-qrcode"
)

// PairingPayload is the JSON structure encoded in the QR code.
type PairingPayload struct {
	Version   int    `json:"version"`
	PublicKey string `json:"publicKey"` // Base64 X.509 encoded Ed25519 public key
	Nonce     string `json:"nonce"`     // Base64 random 32 bytes
	Label     string `json:"label"`
	Signature string `json:"signature"` // Base64 Ed25519 signature of nonce
}

// DeviceKeys holds the proxy's Ed25519 keypair.
type DeviceKeys struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// Config holds pairing configuration.
type Config struct {
	KeysDir string
	Label   string
}

// LoadOrGenerateKeys loads existing keys or generates new ones.
func LoadOrGenerateKeys(keysDir string) (*DeviceKeys, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys dir: %w", err)
	}

	privPath := filepath.Join(keysDir, "device.key")
	pubPath := filepath.Join(keysDir, "device.pub")

	// Try loading existing keys
	privBytes, err := os.ReadFile(privPath)
	if err == nil {
		privKey := ed25519.PrivateKey(privBytes)
		pubKey := privKey.Public().(ed25519.PublicKey)
		log.Println("Loaded existing device keypair")
		return &DeviceKeys{PrivateKey: privKey, PublicKey: pubKey}, nil
	}

	// Generate new keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	if err := os.WriteFile(privPath, privKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubKey, 0644); err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}

	log.Println("Generated new device keypair")
	return &DeviceKeys{PrivateKey: privKey, PublicKey: pubKey}, nil
}

// GenerateQR creates a pairing QR code and saves it as a PNG file.
// Also prints the QR to the terminal.
func GenerateQR(keys *DeviceKeys, label string, outputPath string) error {
	// Generate random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Sign the nonce
	signature := ed25519.Sign(keys.PrivateKey, nonce)

	// Encode public key in X.509/PKIX format
	x509PubKey, err := x509.MarshalPKIXPublicKey(keys.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	payload := PairingPayload{
		Version:   1,
		PublicKey: base64.RawStdEncoding.EncodeToString(x509PubKey),
		Nonce:     base64.RawStdEncoding.EncodeToString(nonce),
		Label:     label,
		Signature: base64.RawStdEncoding.EncodeToString(signature),
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Generate QR code
	qr, err := qrcode.New(string(jsonBytes), qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Print to terminal
	fmt.Println("\n=== Scan this QR code with PocketSSHAgent app ===")
	fmt.Println(qr.ToSmallString(false))

	// Save as PNG
	if outputPath != "" {
		if err := qr.WriteFile(256, outputPath); err != nil {
			return fmt.Errorf("failed to write QR PNG: %w", err)
		}
		log.Printf("QR code saved to: %s", outputPath)
	}

	return nil
}
