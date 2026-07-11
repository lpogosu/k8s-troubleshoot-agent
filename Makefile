BINARY      := kubediag
BIN_DIR     := bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GOLANGCI    := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6

# The fixture the demo target diagnoses. It is a snapshot of a cluster with
# several unrelated faults at once, which is what makes the severity ordering
# visible.
DEMO_SNAPSHOT := internal/rules/testdata/mixed-incident.json

.PHONY: help build test lint fmt cover demo demo-json rules install clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary into bin/
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/kubediag

test: ## Run every test; needs no cluster and no network
	go test -race ./...

lint: ## Run golangci-lint with the repository configuration
	$(GOLANGCI) run ./...

fmt: ## Format the tree
	gofmt -w ./cmd ./internal

# -coverpkg is needed because most of snapshot/ and report/ is exercised by the
# rules package's fixture tests, and Go does not credit cross-package coverage
# without it. The two trees are named explicitly rather than with ./... so the
# figure cannot quietly grow to include the standard library.
COVERPKG := ./cmd/...,./internal/...

cover: ## Report total test coverage
	go test -coverpkg='$(COVERPKG)' -coverprofile=coverage.out ./cmd/... ./internal/... > /dev/null
	@go tool cover -func=coverage.out | tail -1

demo: build ## Diagnose the bundled incident snapshot — no cluster required
	@echo "==> kubediag diagnose -f $(DEMO_SNAPSHOT)"
	@echo
	@./$(BIN_DIR)/$(BINARY) diagnose -f $(DEMO_SNAPSHOT)

demo-json: build ## The same run as JSON
	@./$(BIN_DIR)/$(BINARY) diagnose -f $(DEMO_SNAPSHOT) -o json

rules: build ## List the rules and what each one detects
	@./$(BIN_DIR)/$(BINARY) rules

install: ## Install kubediag into GOBIN
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/kubediag

clean: ## Remove build output
	rm -rf $(BIN_DIR) coverage.out
