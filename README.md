# IDCLI

A command-line interface for OAuth2 authentication with Keycloak, supporting both PKCE and Client Credentials flows.

## Installation

### One-line Install
```bash
curl -sSL https://raw.githubusercontent.com/prefeitura-rio/idcli/main/install.sh | bash
```

### From Source
```bash
# Clone the repository
git clone https://github.com/prefeitura-rio/idcli.git
cd idcli

# Install dependencies
go mod tidy

# Build the project
go build -o idcli
```

### From Release
Download the latest release from the [releases page](https://github.com/prefeitura-rio/idcli/releases) and extract the binary for your platform.

## Configuration

Create a configuration file with your OAuth2 settings. You can use `config_example.yaml` as a template:

```bash
# Copy the example config
cp config_example.yaml config.yaml

# Edit the config with your settings
vim config.yaml
```

The configuration file must follow this structure:

```yaml
oauth2:
  issuer: "https://your-keycloak-url/auth/realms/your-realm"
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  redirect_uri: "http://localhost:8000/callback"
  scopes:
    - "openid"
    - "profile"
    - "address"
    - "phone"
    - "roles"
```

The configuration file path must be specified in one of these ways:
1. Command line flag: `--config` or `-c`
2. Environment variable: `IDCLI_CONFIG_YAML_PATH`

## Usage

### PKCE Flow (Default)
Interactive flow that opens a browser for authentication:

```bash
# Run with specific config file
./idcli --config /path/to/config.yaml

# Run with config path from environment
export IDCLI_CONFIG_YAML_PATH=/path/to/config.yaml
./idcli
```

### Client Credentials Flow
Direct machine-to-machine authentication (requires client_secret in config):

```bash
# Use client credentials flow
./idcli --config /path/to/config.yaml --client-credentials
```

This flow makes a direct API call without requiring browser interaction, perfect for automated scripts and server-to-server authentication.

## Development

This project uses [just](https://github.com/casey/just) for development commands:

```bash
# List available commands
just

# Build the project
just build

# Run the project
just run

# Format code
just fmt

# Run linter
just lint

# Run tests
just test

# Build for multiple platforms
just build-all
```

## Releases

This project uses [GoReleaser](https://goreleaser.com) to create releases. When a new tag is pushed, GitHub Actions will automatically:

1. Build binaries for multiple platforms (Linux, macOS, Windows)
2. Create a GitHub release
3. Attach the binaries to the release

To create a new release:

```bash
# Create and push a new tag
git tag v1.0.0
git push origin v1.0.0
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 