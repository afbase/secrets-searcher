# secrets-searcher

[![CI](https://github.com/afbase/secrets-searcher/actions/workflows/ci.yml/badge.svg)](https://github.com/afbase/secrets-searcher/actions/workflows/ci.yml)
[![Release](https://github.com/afbase/secrets-searcher/actions/workflows/release.yml/badge.svg)](https://github.com/afbase/secrets-searcher/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/afbase/secrets-searcher)](https://goreportcard.com/report/github.com/afbase/secrets-searcher)

A powerful, configurable tool for searching sensitive information in git repositories. Scan repositories for API keys, tokens, passwords, and other secrets that may have been accidentally committed.

Inspired by [truffleHog](https://github.com/trufflesecurity/truffleHog) and [shhgit](https://github.com/eth0izzle/shhgit).

## Features

- **28+ Built-in Secret Detectors**: Detects AWS keys, GitHub tokens, Digital Ocean tokens, Stripe keys, database passwords, and more
- **Custom Rules**: Define your own detection patterns using regex or setter-based rules
- **Multiple Sources**: Scan GitHub organizations, local repositories, or specific commits
- **Flexible Configuration**: YAML-based configuration with environment variable support
- **Rich Reporting**: Generate HTML reports with detailed findings
- **Entropy Detection**: Identify high-entropy strings that may be secrets (Base64, Hex)
- **Performance**: Concurrent scanning with configurable worker pools
- **GitHub Integration**: Native support for scanning entire GitHub organizations

### Supported Secret Types

The tool includes built-in detectors for:

**Cloud Providers:**
- AWS Access Key ID, Secret Key, MWS Auth Token
- Digital Ocean Personal Access Tokens, OAuth Tokens, Refresh Tokens

**Version Control:**
- GitHub Tokens, OAuth Tokens
- SSH Private Keys (RSA, DSA, EC, OpenSSH)

**Payment Processors:**
- Stripe API Keys
- Square Access Tokens, OAuth Secrets
- PayPal Braintree Access Tokens

**Email & Communication:**
- SendGrid API Keys
- MailGun API Keys
- MailChimp API Keys
- Twilio API Keys, Account SIDs
- Slack Tokens, Webhooks

**Development Tools:**
- NuGet API Keys
- LinkedIn Client IDs, Secret Keys
- NPM Tokens
- PyPI Upload Tokens

**Database & Services:**
- URL-embedded passwords (database connection strings, etc.)
- Generic API keys
- Base64/Hex entropy detection

## Installation

### From Source

Requirements: Go 1.23 or later

```bash
git clone https://github.com/afbase/secrets-searcher.git
cd secrets-searcher
make build
```

The binary will be created as `secrets-searcher` in the current directory.

### Using Go Install

```bash
go install github.com/afbase/secrets-searcher@latest
```

### Pre-built Binaries

Download pre-built binaries from the [releases page](https://github.com/afbase/secrets-searcher/releases).

## Quick Start

### Scanning a GitHub Organization

1. Generate a GitHub Personal Access Token with `repo` scope:
   - Go to GitHub Settings → Developer settings → Personal access tokens → Generate new token
   - Select `repo` scope
   - Copy the generated token

2. Set up your configuration:

```bash
cd example_config
export SECRETS_SOURCE_API_TOKEN="your-github-token-here"
../secrets-searcher --config="config.yaml,config.rules.yaml"
```

3. View the report in `./output/report/index.html`

### Scanning a Local Repository

Create a configuration file `config.yaml`:

```yaml
source:
  type: local
  local:
    path: /path/to/your/repo

search:
  processors:
    - URLPasswordRegex
    - GitHubTokenRegex
    - AWSAccessKeyIDRegex
    - StripeAPIKeyRegex
    # Add more processors as needed

reporter:
  type: html
  html:
    output_dir: ./output/report
```

Run the scan:

```bash
secrets-searcher --config=config.yaml
```

## Configuration

### Configuration Files

The tool accepts multiple YAML configuration files that are merged together:

```bash
secrets-searcher --config="config.yaml,config.rules.yaml,config.custom.yaml"
```

### Environment Variables

All configuration values can be overridden using environment variables with the `SECRETS_` prefix:

```bash
export SECRETS_SOURCE_API_TOKEN="ghp_xxxxx"
export SECRETS_SOURCE_GITHUB_ORGS="myorg1,myorg2"
secrets-searcher --config=config.yaml
```

### Example Configuration

See the [example_config](./example_config) directory for complete configuration examples.

### Custom Rules

Define custom detection patterns in your configuration:

```yaml
search:
  processors:
    - name: MyCustomAPIKey
      processor: regex
      regex:
        regex_string: "myapp_key_[A-Za-z0-9]{32}"
```

## Usage

### Command-Line Options

```bash
# Show version information
secrets-searcher --version

# Show help
secrets-searcher --help

# Run with configuration
secrets-searcher --config=config.yaml

# Run with multiple configs (merged in order)
secrets-searcher --config="base.yaml,overrides.yaml"
```

### Makefile Targets

```bash
make help                 # Show available targets
make build               # Build with version information
make test                # Run tests with race detector
make test-coverage       # Generate coverage report
make test-coverage-html  # Generate HTML coverage report
make lint                # Format code
make clean               # Clean build artifacts
make version             # Show build version info
```

## Development

### Prerequisites

- Go 1.23 or later
- Git

### Building

```bash
make build
```

This will inject version information from git into the binary.

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Generate HTML coverage report
make test-coverage-html
```

### Code Quality

```bash
# Format code
make lint

# Check for unchecked errors
make errcheck
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Adding New Secret Detectors

To add a new secret detector:

1. Add the detector definition to `pkg/builtin/processor.go`
2. Add the processor name constant to `pkg/builtin/processorname.go`
3. Run `go generate` to update auto-generated files
4. Add tests to `pkg/builtin/processor_test.go`

## License

See the [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability, please email security@afbase.com instead of using the issue tracker.

## Acknowledgments

- Inspired by [truffleHog](https://github.com/trufflesecurity/truffleHog)
- Inspired by [shhgit](https://github.com/eth0izzle/shhgit)
- Built with [go-git](https://github.com/go-git/go-git)
