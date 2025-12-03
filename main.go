package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	version = "0.3.7"
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

type TokenCache struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
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

func extractFromTarGz(archiveData []byte, filename string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if filepath.Base(header.Name) == filename {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("file %s not found in archive", filename)
}

func extractFromZip(archiveData []byte, filename string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if err != nil {
		return nil, err
	}

	for _, file := range zr.File {
		if filepath.Base(file.Name) == filename {
			rc, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("file %s not found in archive", filename)
}

func getTokenCachePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(homeDir, ".idcli")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "token.json"), nil
}

func saveTokenCache(token *TokenCache) error {
	cachePath, err := getTokenCachePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0600)
}

func loadTokenCache() (*TokenCache, error) {
	cachePath, err := getTokenCachePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var token TokenCache
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func clearTokenCache() error {
	cachePath, err := getTokenCachePath()
	if err != nil {
		return err
	}
	return os.Remove(cachePath)
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
		return fmt.Errorf("network error requesting tokens: %w\n\nHint: Check your internet connection and that the issuer URL is correct", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseOAuthError(body, resp.StatusCode)
	}

	// Parse and cache the token response
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return fmt.Errorf("parsing token response: %w", err)
	}

	// Save to cache
	cache := &TokenCache{
		AccessToken: tokenResponse["access_token"].(string),
		TokenType:   getStringOrEmpty(tokenResponse, "token_type"),
	}
	if refreshToken, ok := tokenResponse["refresh_token"].(string); ok {
		cache.RefreshToken = refreshToken
	}
	if expiresIn, ok := tokenResponse["expires_in"].(float64); ok {
		cache.ExpiresAt = time.Now().Unix() + int64(expiresIn)
	}

	if err := saveTokenCache(cache); err != nil {
		fmt.Printf("Warning: failed to cache token: %v\n", err)
	}

	// Pretty print the tokens
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
		return fmt.Errorf("formatting JSON: %w", err)
	}
	fmt.Printf("\nReceived tokens:\n%s\n", prettyJSON.String())

	return nil
}

func getStringOrEmpty(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func parseOAuthError(body []byte, statusCode int) error {
	var oauthErr OAuthError
	if err := json.Unmarshal(body, &oauthErr); err == nil && oauthErr.Error != "" {
		msg := fmt.Sprintf("OAuth error (%d): %s", statusCode, oauthErr.Error)
		if oauthErr.ErrorDescription != "" {
			msg += fmt.Sprintf(" - %s", oauthErr.ErrorDescription)
		}

		// Add helpful hints based on error type
		switch oauthErr.Error {
		case "invalid_client":
			msg += "\n\nHint: Check that your client_id and client_secret are correct in the config file"
		case "invalid_grant":
			msg += "\n\nHint: The authorization code may have expired or already been used. Try authenticating again"
		case "unauthorized_client":
			msg += "\n\nHint: This client is not authorized for the requested grant type. Check your Keycloak client configuration"
		case "access_denied":
			msg += "\n\nHint: The user denied the authorization request"
		case "invalid_scope":
			msg += "\n\nHint: One or more requested scopes are invalid. Check the 'scopes' in your config file"
		}

		return fmt.Errorf(msg)
	}

	return fmt.Errorf("request failed with status %d: %s", statusCode, string(body))
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
	var refreshToken bool

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

			// Check for cached token unless --refresh is set
			if !refreshToken {
				if cachedToken, err := loadTokenCache(); err == nil {
					// Check if token is expired
					if cachedToken.ExpiresAt == 0 || cachedToken.ExpiresAt > time.Now().Unix() {
						fmt.Println("Using cached token")
						fmt.Printf("Access Token: %s\n", cachedToken.AccessToken)
						if cachedToken.RefreshToken != "" {
							fmt.Printf("Refresh Token: %s\n", cachedToken.RefreshToken)
						}
						if cachedToken.ExpiresAt > 0 {
							expiresIn := cachedToken.ExpiresAt - time.Now().Unix()
							fmt.Printf("Expires in: %d seconds\n", expiresIn)
						}
						fmt.Println("\nUse --refresh to force re-authentication")
						return nil
					}
					fmt.Println("Cached token expired, re-authenticating...")
				}
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
				return fmt.Errorf("network error exchanging code for tokens: %w\n\nHint: Check your internet connection and that the issuer URL is correct", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("reading response: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				return parseOAuthError(body, resp.StatusCode)
			}

			// Parse and cache the token response
			var tokenResponse map[string]interface{}
			if err := json.Unmarshal(body, &tokenResponse); err != nil {
				return fmt.Errorf("parsing token response: %w", err)
			}

			// Save to cache
			cache := &TokenCache{
				AccessToken: tokenResponse["access_token"].(string),
				TokenType:   getStringOrEmpty(tokenResponse, "token_type"),
			}
			if refreshToken, ok := tokenResponse["refresh_token"].(string); ok {
				cache.RefreshToken = refreshToken
			}
			if expiresIn, ok := tokenResponse["expires_in"].(float64); ok {
				cache.ExpiresAt = time.Now().Unix() + int64(expiresIn)
			}

			if err := saveTokenCache(cache); err != nil {
				fmt.Printf("Warning: failed to cache token: %v\n", err)
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
	rootCmd.Flags().BoolVar(&refreshToken, "refresh", false, "force re-authentication even if token is cached")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("idcli version %s\n", version)

			// Check for latest version
			latestVersion, err := checkLatestVersion()
			if err != nil {
				// Silently fail - don't bother the user with network errors
				return
			}

			currentVersion := strings.TrimPrefix(version, "v")
			if latestVersion == currentVersion {
				fmt.Println("✓ You're on the latest version")
			} else if latestVersion > currentVersion {
				fmt.Printf("⚠️  Update available: v%s → v%s\n", currentVersion, latestVersion)
				fmt.Println("Run 'idcli upgrade' to update")
			}
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

			// Determine archive name based on platform (GoReleaser format)
			var archiveName, archFormat string
			var osName, archName string

			switch runtime.GOOS {
			case "darwin":
				osName = "Darwin"
			case "linux":
				osName = "Linux"
			case "windows":
				osName = "Windows"
			default:
				return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
			}

			switch runtime.GOARCH {
			case "amd64":
				archName = "x86_64"
			case "arm64":
				archName = "arm64"
			default:
				return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
			}

			// Windows uses zip, others use tar.gz
			if runtime.GOOS == "windows" {
				archFormat = "zip"
			} else {
				archFormat = "tar.gz"
			}

			archiveName = fmt.Sprintf("idcli_%s_%s.%s", osName, archName, archFormat)
			downloadURL := fmt.Sprintf("%s/releases/download/v%s/%s", repoURL, latestVersion, archiveName)
			fmt.Printf("Downloading from %s...\n", downloadURL)

			// Download the archive
			resp, err := http.Get(downloadURL)
			if err != nil {
				return fmt.Errorf("downloading archive: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("download failed with status %d", resp.StatusCode)
			}

			// Read archive into memory
			archiveData, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("reading archive: %w", err)
			}

			// Extract binary from archive
			var binaryData []byte
			if archFormat == "zip" {
				binaryData, err = extractFromZip(archiveData, "idcli.exe")
			} else {
				binaryData, err = extractFromTarGz(archiveData, "idcli")
			}
			if err != nil {
				return fmt.Errorf("extracting binary: %w", err)
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

			// Write the binary to temp file
			if _, err := tmpFile.Write(binaryData); err != nil {
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
				// If permission denied, try using sudo
				if os.IsPermission(err) {
					fmt.Println("Permission denied. Attempting to upgrade with sudo...")

					// Use sudo to move the file
					cmd := exec.Command("sudo", "mv", tmpPath, execPath)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Stdin = os.Stdin

					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to upgrade with sudo: %w", err)
					}
				} else {
					return fmt.Errorf("replacing binary: %w", err)
				}
			}

			fmt.Printf("✓ Successfully upgraded to v%s\n", latestVersion)
			return nil
		},
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the cached token",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load cached token
			cachedToken, err := loadTokenCache()
			if err != nil {
				return fmt.Errorf("no cached token found\n\nRun 'idcli' to authenticate first")
			}

			fmt.Println("Cached token found")
			fmt.Printf("Token type: %s\n", cachedToken.TokenType)

			// Check expiration
			if cachedToken.ExpiresAt == 0 {
				fmt.Println("Status: ✓ Valid (no expiration)")
			} else if cachedToken.ExpiresAt > time.Now().Unix() {
				expiresIn := cachedToken.ExpiresAt - time.Now().Unix()
				fmt.Printf("Status: ✓ Valid (expires in %d seconds / ~%d minutes)\n", expiresIn, expiresIn/60)
			} else {
				expiredAgo := time.Now().Unix() - cachedToken.ExpiresAt
				fmt.Printf("Status: ✗ Expired (%d seconds ago / ~%d minutes ago)\n", expiredAgo, expiredAgo/60)
				fmt.Println("\nRun 'idcli --refresh' to re-authenticate")
				return fmt.Errorf("token expired")
			}

			// Show token info
			fmt.Printf("\nAccess Token: %s\n", cachedToken.AccessToken)
			if cachedToken.RefreshToken != "" {
				fmt.Printf("Refresh Token: %s\n", cachedToken.RefreshToken)
			}

			return nil
		},
	}

	clearCmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear the cached token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := clearTokenCache(); err != nil {
				if os.IsNotExist(err) {
					fmt.Println("No cached token to clear")
					return nil
				}
				return fmt.Errorf("failed to clear token cache: %w", err)
			}
			fmt.Println("✓ Token cache cleared")
			return nil
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(clearCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
} 