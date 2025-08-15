package main

import (
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier() error = %v", err)
	}
	
	if len(verifier) == 0 {
		t.Error("generateCodeVerifier() returned empty string")
	}
	
	// Check that it generates different values each time
	verifier2, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier() second call error = %v", err)
	}
	
	if verifier == verifier2 {
		t.Error("generateCodeVerifier() returned same value twice")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "test-verifier-123"
	challenge := generateCodeChallenge(verifier)
	
	if len(challenge) == 0 {
		t.Error("generateCodeChallenge() returned empty string")
	}
	
	// Same input should produce same output
	challenge2 := generateCodeChallenge(verifier)
	if challenge != challenge2 {
		t.Error("generateCodeChallenge() returned different values for same input")
	}
}

func TestLoadConfig(t *testing.T) {
	// Test with non-existent file
	_, err := loadConfig("non-existent-file.yaml")
	if err == nil {
		t.Error("loadConfig() should return error for non-existent file")
	}
	
	// Test with example config
	config, err := loadConfig("config_example.yaml")
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	
	if config.OAuth2.Issuer == "" {
		t.Error("loadConfig() did not parse issuer")
	}
	
	if config.OAuth2.ClientID == "" {
		t.Error("loadConfig() did not parse client_id")
	}
	
	if len(config.OAuth2.Scopes) == 0 {
		t.Error("loadConfig() did not parse scopes")
	}
}