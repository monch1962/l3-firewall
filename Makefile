GO_BIN := /usr/local/go/bin/go
GOLANGCI_BIN := $(HOME)/go/bin/golangci-lint
NILAWAY_BIN := $(HOME)/go/bin/nilaway
OPA_BIN := $(HOME)/.local/bin/opa
BINARY := l3-firewall
LD_FLAGS := -ldflags="-s -w"

.PHONY: all build test lint vet nilaway docker clean help

all: lint vet build test

build:
	$(GO_BIN) build $(LD_FLAGS) -trimpath -o $(BINARY) ./cmd/server/

test:
	$(GO_BIN) test ./... -count=1 -v
	$(OPA_BIN) test opa-policies/ -v

test-go:
	$(GO_BIN) test ./... -count=1 -v

test-opa:
	$(OPA_BIN) test opa-policies/ -v

lint:
	$(GOLANGCI_BIN) run --timeout 2m

vet:
	$(GO_BIN) vet ./...

nilaway:
	$(NILAWAY_BIN) -include-pkgs="github.com/monch1962/l3-firewall/internal/packet,\
		github.com/monch1962/l3-firewall/internal/engine,\
		github.com/monch1962/l3-firewall/internal/opa,\
		github.com/monch1962/l3-firewall/internal/conntrack,\
		github.com/monch1962/l3-firewall/internal/ratelimit,\
		github.com/monch1962/l3-firewall/internal/metrics,\
		github.com/monch1962/l3-firewall/internal/admin,\
		github.com/monch1962/l3-firewall/cmd/server" ./... 2>&1 | grep -v "_test.go" | grep -q "error:" && echo "FAILED" || echo "nilaway: PASS"

docker:
	docker build -t $(BINARY):latest .

clean:
	rm -f $(BINARY)
	rm -rf /tmp/l3-firewall-*
	$(GO_BIN) clean ./...

help:
	@echo "Targets:"
	@echo "  build     - build Go binary"
	@echo "  test      - run all Go and Rego tests"
	@echo "  test-go   - run Go tests only"
	@echo "  test-opa  - run Rego tests only"
	@echo "  lint      - run golangci-lint"
	@echo "  vet       - run go vet"
	@echo "  nilaway   - run nilaway (production code only)"
	@echo "  docker    - build Docker image"
	@echo "  clean     - remove binary and build cache"
	@echo "  all       - lint, vet, build, test"
