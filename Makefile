APP=secrets-searcher

# Commands
GOCMD=go
GOIMPORTS=goimports
ERRCHECK=errcheck
GOGENERATE=$(GOCMD) generate
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOLIST=$(GOCMD) list
BINARY_NAME=$(APP)

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS=-ldflags "-X github.com/afbase/secrets-searcher/pkg/app/vars.Version=$(VERSION) \
	-X github.com/afbase/secrets-searcher/pkg/app/vars.Commit=$(COMMIT) \
	-X github.com/afbase/secrets-searcher/pkg/app/vars.Date=$(DATE)"

.PHONY: all generate errcheck lint build build-linux build-race test test-coverage test-coverage-html clean version help

all: test build

help:
	@echo "Available targets:"
	@echo "  all              - Run tests and build"
	@echo "  build            - Build the binary with version info"
	@echo "  build-linux      - Build Linux AMD64 binary"
	@echo "  build-race       - Build with race detector"
	@echo "  test             - Run all tests with race detector"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-coverage-html - Generate HTML coverage report"
	@echo "  generate         - Run go generate"
	@echo "  lint             - Format code with goimports"
	@echo "  errcheck         - Check for unchecked errors"
	@echo "  clean            - Clean build artifacts"
	@echo "  version          - Show version information"

version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"

generate:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...

errcheck:
	$(ERRCHECK) . ./cmd/... ./pkg/...

lint:
	$(GOIMPORTS) -w $(shell $(GOLIST) -f "{{.Dir}}" ./cmd/... ./pkg/...)

build:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v

build-linux:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux -v

build-race:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...
	$(GOBUILD) -race $(LDFLAGS) -o $(BINARY_NAME) -v

test:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...
	$(GOTEST) -race -v . ./cmd/... ./pkg/...

test-coverage:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...
	$(GOTEST) -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -func=coverage.out

test-coverage-html:
	$(GOGENERATE) -v . ./cmd/... ./pkg/...
	$(GOTEST) -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) $(BINARY_NAME)-linux
	rm -f coverage.out coverage.html
