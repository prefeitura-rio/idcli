package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Config struct {
	OAuth2 struct {
		Issuer       string   `yaml:"issuer"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		RedirectURI  string   `yaml:"redirect_uri"`
		Scopes       []string `yaml:"scopes"`
	} `yaml:"oauth2"`
}

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return &config, nil
}

func performClientCredentialsFlow(config *Config) error {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", config.OAuth2.Issuer)
	data := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     config.OAuth2.ClientID,
		"client_secret": config.OAuth2.ClientSecret,
		"scope":         "profile email",
	}

	var formParts []string
	for k, v := range data {
		formParts = append(formParts, fmt.Sprintf("%s=%s", k, v))
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded",
		strings.NewReader(strings.Join(formParts, "&")))
	if err != nil {
		return fmt.Errorf("requesting tokens: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Pretty print the tokens
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
		return fmt.Errorf("formatting JSON: %w", err)
	}
	fmt.Printf("\nReceived tokens:\n%s\n", prettyJSON.String())

	return nil
}

func startCallbackServer(codeChan chan string) {
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "" {
			codeChan <- code
			fmt.Fprintf(w, "Authentication successful! You can close this window.")
		} else {
			http.Error(w, "No code received", http.StatusBadRequest)
		}
	})

	go func() {
		if err := http.ListenAndServe(":8000", nil); err != nil {
			fmt.Printf("Error starting callback server: %v\n", err)
		}
	}()
}

func main() {
	var configPath string
	var useClientCredentials bool

	rootCmd := &cobra.Command{
		Use:   "idcli",
		Short: "OAuth2 CLI client with PKCE and Client Credentials flows",
		RunE: func(cmd *cobra.Command, args []string) error {
			// If config path not provided via flag, try environment variable
			if configPath == "" {
				configPath = os.Getenv("IDCLI_CONFIG_YAML_PATH")
			}
			// If still not set, return error
			if configPath == "" {
				return fmt.Errorf("config path is required. Please provide it either through --config flag or IDCLI_CONFIG_YAML_PATH environment variable")
			}

			config, err := loadConfig(configPath)
			if err != nil {
				return fmt.Errorf("loading config from %s: %w", configPath, err)
			}

			// Use client credentials flow if flag is set
			if useClientCredentials {
				if config.OAuth2.ClientSecret == "" {
					return fmt.Errorf("client_secret is required for client credentials flow")
				}
				return performClientCredentialsFlow(config)
			}

			// Generate PKCE values
			codeVerifier, err := generateCodeVerifier()
			if err != nil {
				return fmt.Errorf("generating code verifier: %w", err)
			}
			codeChallenge := generateCodeChallenge(codeVerifier)

			// Start callback server
			codeChan := make(chan string)
			startCallbackServer(codeChan)

			// Build authorization URL
			authURL := fmt.Sprintf("%s/protocol/openid-connect/auth", config.OAuth2.Issuer)
			params := map[string]string{
				"client_id":             config.OAuth2.ClientID,
				"response_type":         "code",
				"scope":                 strings.Join(config.OAuth2.Scopes, "+"),
				"redirect_uri":          config.OAuth2.RedirectURI,
				"code_challenge":        codeChallenge,
				"code_challenge_method": "S256",
			}

			var queryParts []string
			for k, v := range params {
				queryParts = append(queryParts, fmt.Sprintf("%s=%s", k, v))
			}
			authURL = fmt.Sprintf("%s?%s", authURL, strings.Join(queryParts, "&"))

			fmt.Printf("Please visit this URL to authenticate:\n%s\n", authURL)

			// Wait for the authorization code
			code := <-codeChan

			// Exchange code for tokens
			tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", config.OAuth2.Issuer)
			data := map[string]string{
				"grant_type":    "authorization_code",
				"client_id":     config.OAuth2.ClientID,
				"code":          code,
				"redirect_uri":  config.OAuth2.RedirectURI,
				"code_verifier": codeVerifier,
			}

			// Add client secret if provided
			if config.OAuth2.ClientSecret != "" {
				data["client_secret"] = config.OAuth2.ClientSecret
			}

			var formParts []string
			for k, v := range data {
				formParts = append(formParts, fmt.Sprintf("%s=%s", k, v))
			}

			resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", 
				strings.NewReader(strings.Join(formParts, "&")))
			if err != nil {
				return fmt.Errorf("exchanging code for tokens: %w", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("reading response: %w", err)
			}

			// Pretty print the tokens
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
				return fmt.Errorf("formatting JSON: %w", err)
			}
			fmt.Printf("\nReceived tokens:\n%s\n", prettyJSON.String())

			return nil
		},
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "path to config file")
	rootCmd.Flags().BoolVar(&useClientCredentials, "client-credentials", false, "use client credentials flow instead of PKCE")
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
} 