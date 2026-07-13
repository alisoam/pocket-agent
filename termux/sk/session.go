package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const sessionInfo = "pocket-ssh-termux-v1"

type TermuxSession struct {
	priv *ecdh.PrivateKey
	key  []byte
}

func NewTermuxSession() (*TermuxSession, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	pubRaw := priv.PublicKey().Bytes()
	return &TermuxSession{priv: priv}, pubRaw, nil
}

func (s *TermuxSession) DeriveKey(serverPubRaw []byte) error {
	theirPub, err := ecdh.X25519().NewPublicKey(serverPubRaw)
	if err != nil {
		return fmt.Errorf("invalid server x25519 key: %w", err)
	}
	sharedSecret, err := s.priv.ECDH(theirPub)
	if err != nil {
		return fmt.Errorf("ecdh: %w", err)
	}
	s.key = hkdfSha256(sharedSecret, make([]byte, 32))
	s.priv = nil
	return nil
}

func (s *TermuxSession) Seal(plaintext []byte) ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("session key not derived")
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm: %w", err)
	}
	return append(nonce, aesgcm.Seal(nil, nonce, plaintext, nil)...), nil
}

func (s *TermuxSession) Open(data []byte) ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("session key not derived")
	}
	if len(data) < 12+16 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}
	nonce := data[:12]
	ciphertext := data[12:]
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm: %w", err)
	}
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func hkdfSha256(sharedSecret, salt []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(sharedSecret)
	prk := mac.Sum(nil)

	mac2 := hmac.New(sha256.New, prk)
	mac2.Write([]byte(sessionInfo))
	mac2.Write([]byte{0x01})
	return mac2.Sum(nil)
}
