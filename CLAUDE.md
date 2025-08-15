# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

This project uses [just](https://github.com/casey/just) for development tasks:

- `just` - List all available commands
- `just build` - Build the CLI binary
- `just run` - Build and run with config.yaml
- `just fmt` - Format Go code
- `just lint` - Run Go vet linter
- `just test` - Run Go tests
- `just dev` - Complete development workflow (format, lint, test, build)
- `just build-all` - Build for multiple platforms (Linux, macOS, Windows)
- `just clean` - Remove build artifacts
- `just deps` - Install/update Go dependencies

Alternative Go commands:
- `go build -o idcli` - Build the binary
- `go mod tidy` - Manage dependencies
- `go fmt ./...` - Format code
- `go vet ./...` - Lint code
- `go test ./...` - Run tests

## Architecture

This is a single-file Go CLI application (`main.go`) that implements OAuth2 authentication for Keycloak with support for both PKCE and Client Credentials flows. Key components:

### Configuration
- Uses YAML config files (see `config_example.yaml`)
- Config path via `--config` flag or `IDCLI_CONFIG_YAML_PATH` env var
- Contains OAuth2 settings: issuer, client_id, client_secret, redirect_uri, scopes

### OAuth2 Flows

#### PKCE Flow (Default)
- Generates PKCE code verifier/challenge using crypto/sha256
- Starts local HTTP server on port 8000 for OAuth callback
- Constructs Keycloak authorization URL with PKCE parameters
- Exchanges authorization code for tokens using client credentials

#### Client Credentials Flow (--client-credentials flag)
- Direct POST to token endpoint with client_id/client_secret
- Uses grant_type "client_credentials" with scope "profile email"
- No browser interaction required - perfect for automation

### Dependencies
- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML parsing
- Built-in Go packages for crypto, HTTP, and JSON handling

### Key Functions
- `generateCodeVerifier()` - Creates PKCE code verifier
- `generateCodeChallenge()` - Generates SHA256 challenge from verifier
- `loadConfig()` - Parses YAML configuration
- `startCallbackServer()` - HTTP server for OAuth callback
- `performClientCredentialsFlow()` - Direct token request for client credentials flow

## Testing and Configuration

- Create `config.yaml` from `config_example.yaml` for local testing
- Configure Keycloak client with `http://localhost:8000/callback` redirect URI
- Supports both confidential and public OAuth2 clients