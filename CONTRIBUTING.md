# Contributing to secrets-searcher

Thank you for your interest in contributing to secrets-searcher! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear, descriptive title
- Detailed steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Go version, etc.)
- Any relevant configuration files (sanitized of secrets!)
- Error messages and logs

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- A clear description of the enhancement
- Use cases and examples
- Why this enhancement would be useful
- Possible implementation approaches (optional)

### Pull Requests

1. **Fork the repository** and create your branch from `main`

2. **Make your changes**:
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure all tests pass

3. **Commit your changes**:
   - Use clear, descriptive commit messages
   - Follow conventional commits format when possible:
     - `feat: add new secret detector for XYZ`
     - `fix: correct regex pattern for AWS keys`
     - `docs: update README with new examples`
     - `test: add tests for Digital Ocean tokens`

4. **Push to your fork** and submit a pull request

5. **Wait for review**:
   - Address any feedback from reviewers
   - Keep your PR up to date with main branch

## Development Setup

### Prerequisites

- Go 1.23 or later
- Git
- Make

### Clone and Build

```bash
git clone https://github.com/afbase/secrets-searcher.git
cd secrets-searcher
make build
```

### Run Tests

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

## Adding New Secret Detectors

### 1. Add Processor Definition

Edit `pkg/builtin/processor.go` and add your detector to the `processorDefinitions()` function:

```go
{
    Name:      MyNewSecretRegex.String(),
    Processor: search.Regex.String(),
    RegexProcessorConfig: config.RegexProcessorConfig{
        RegexString: `your-regex-pattern-here`,
    },
},
```

### 2. Add Processor Name

Edit `pkg/builtin/processorname.go` and add your constant:

```go
const (
    // ... existing constants
    MyNewSecretRegex ProcessorName = iota + 200
)
```

### 3. Generate Code

Run code generation to update auto-generated string methods:

```bash
make generate
```

### 4. Add Tests

Edit `pkg/builtin/processor_test.go` and add tests for your detector:

```go
func TestProcessor_MyNewSecret_Valid(t *testing.T) {
    runProcessorTest(t, processorTest{
        coreProcessor: builtin.MyNewSecretRegex,
        line:          xorDecode("encoded-test-data"),
        expMatch:      true,
        expSecret:     xorDecode("encoded-secret-value"),
    })
}

func TestProcessor_MyNewSecret_Invalid(t *testing.T) {
    runProcessorTest(t, processorTest{
        coreProcessor: builtin.MyNewSecretRegex,
        line:          "this should not match",
        expMatch:      false,
    })
}
```

**Important**: Use XOR encoding for test data to avoid triggering GitHub's secret scanning:

```go
// To encode test data:
encoded := xorEncode("your-test-secret-here")
// Then use xorDecode() in your tests
```

### 5. Test Your Changes

```bash
# Run tests
make test

# Build to ensure everything compiles
make build
```

## Regular Expression Guidelines

When writing regex patterns for secret detection:

1. **Be Specific**: Avoid overly broad patterns that cause false positives
2. **Use Anchors**: Use `\b` word boundaries or other anchors when appropriate
3. **Test Thoroughly**: Test against both valid secrets and common false positives
4. **Consider Context**: Think about where the secret might appear (code, configs, etc.)
5. **Check Entropy**: For generic patterns, consider if entropy detection is more appropriate

### Example Pattern Analysis

```go
// Too broad - will match many false positives
RegexString: `api_key.*`

// Better - specific format
RegexString: `\b(myservice_[A-Za-z0-9]{32})\b`

// Best - captures the secret value specifically
RegexString: `myservice_key=([A-Za-z0-9]{32})`
```

## Testing Best Practices

1. **Test both positive and negative cases**
2. **Test edge cases** (empty strings, special characters, etc.)
3. **Use realistic test data** (but XOR encoded)
4. **Test for common false positives**
5. **Ensure tests are deterministic**

## Documentation Guidelines

When updating documentation:

1. **Keep it clear and concise**
2. **Provide examples** where helpful
3. **Update all relevant docs** (README, inline comments, etc.)
4. **Use proper markdown formatting**
5. **Spell check your changes**

## Release Process

Releases are automated via GitHub Actions when tags are pushed:

1. Version is determined by git tags
2. GoReleaser builds binaries for multiple platforms
3. Release is published to GitHub Releases

## Questions?

If you have questions about contributing:

1. Check existing issues and discussions
2. Review the documentation
3. Open a new issue with your question

## Recognition

Contributors will be recognized in:

- Git commit history
- GitHub contributors page
- Release notes (for significant contributions)

Thank you for contributing to secrets-searcher!
