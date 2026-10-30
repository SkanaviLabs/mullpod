.PHONY: build run test verify smoke clean

BIN := bin/mullpod
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.env:
	@echo "Missing .env: cp .env.example .env and fill in the WireGuard key/address"; exit 1

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BIN) .

run: .env build  ## foreground; Ctrl-C stops it
	./$(BIN)

test:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./... && go test -race -count=1 -cover ./...

verify:  ## live checks against a running instance (make run in another terminal)
	./scripts/verify.sh

smoke:
	python3 test/playwright_smoke.py

clean:
	rm -rf bin
