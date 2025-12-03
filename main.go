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
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	version = "0.3.1"
	repoURL = "https://github.com/prefeitura-rio/idcli"
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

type GitHubRelease struct {
	TagName string `json:"tag_name"`
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

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		return fmt.Errorf("unsupported platform")
	}

	return exec.Command(cmd, args...).Start()
}

func checkLatestVersion() (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/prefeitura-rio/idcli/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch latest release: status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	return strings.TrimPrefix(release.TagName, "v"), nil
}

func checkForUpdates() {
	latestVersion, err := checkLatestVersion()
	if err != nil {
		// Silently fail - don't bother the user
		return
	}

	currentVersion := strings.TrimPrefix(version, "v")
	if latestVersion != currentVersion && latestVersion > currentVersion {
		fmt.Printf("\n⚠️  A new version is available: v%s (current: v%s)\n", latestVersion, currentVersion)
		fmt.Printf("Run 'idcli upgrade' to update\n\n")
	}
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
			// Check for updates asynchronously (non-blocking)
			go checkForUpdates()

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

			fmt.Printf("Opening browser for authentication...\n%s\n", authURL)
			if err := openBrowser(authURL); err != nil {
				fmt.Printf("Failed to open browser automatically: %v\n", err)
				fmt.Println("Please visit the URL above manually.")
			}

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

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("idcli version %s\n", version)
		},
	}

	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Checking for latest version...")
			latestVersion, err := checkLatestVersion()
			if err != nil {
				return fmt.Errorf("failed to check for updates: %w", err)
			}

			currentVersion := strings.TrimPrefix(version, "v")
			if latestVersion == currentVersion {
				fmt.Printf("You're already on the latest version (v%s)\n", currentVersion)
				return nil
			}

			fmt.Printf("Upgrading from v%s to v%s...\n", currentVersion, latestVersion)

			// Determine binary name based on platform
			var binaryName string
			switch runtime.GOOS {
			case "darwin":
				switch runtime.GOARCH {
				case "amd64":
					binaryName = "idcli-darwin-amd64"
				case "arm64":
					binaryName = "idcli-darwin-arm64"
				default:
					return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
				}
			case "linux":
				if runtime.GOARCH == "amd64" {
					binaryName = "idcli-linux-amd64"
				} else {
					return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
				}
			case "windows":
				if runtime.GOARCH == "amd64" {
					binaryName = "idcli-windows-amd64.exe"
				} else {
					return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
				}
			default:
				return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
			}

			downloadURL := fmt.Sprintf("%s/releases/download/v%s/%s", repoURL, latestVersion, binaryName)
			fmt.Printf("Downloading from %s...\n", downloadURL)

			// Download the new binary
			resp, err := http.Get(downloadURL)
			if err != nil {
				return fmt.Errorf("downloading binary: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("download failed with status %d", resp.StatusCode)
			}

			// Get the path of the current executable
			execPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("getting executable path: %w", err)
			}

			// Create a temporary file
			tmpFile, err := os.CreateTemp("", "idcli-*")
			if err != nil {
				return fmt.Errorf("creating temp file: %w", err)
			}
			tmpPath := tmpFile.Name()
			defer os.Remove(tmpPath)

			// Write the downloaded binary to temp file
			if _, err := io.Copy(tmpFile, resp.Body); err != nil {
				tmpFile.Close()
				return fmt.Errorf("writing binary: %w", err)
			}
			tmpFile.Close()

			// Make it executable
			if err := os.Chmod(tmpPath, 0755); err != nil {
				return fmt.Errorf("setting permissions: %w", err)
			}

			// Replace the current binary
			if err := os.Rename(tmpPath, execPath); err != nil {
				return fmt.Errorf("replacing binary: %w", err)
			}

			fmt.Printf("✓ Successfully upgraded to v%s\n", latestVersion)
			return nil
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
} 