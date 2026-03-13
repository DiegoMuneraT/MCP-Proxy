BINARY   := mcpfw
CMD_PATH := ./cmd/mcpfw
VERSION  := 0.1.0

.PHONY: build run validate list-rules test test-verbose test-race coverage lint clean release

build:
	go build -ldflags="-X main.version=$(VERSION)" -o $(BINARY) $(CMD_PATH)

run: build
	./$(BINARY) start

validate: build
	./$(BINARY) validate

list-rules: build
	./$(BINARY) list-rules

test:
	go test ./...

test-verbose:
	go test -v ./...

test-race:
	go test -race ./...

coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | grep total

lint:
	go vet ./...
	@which golangci-lint > /dev/null && golangci-lint run || echo "golangci-lint not installed, skipping"

clean:
	rm -f $(BINARY) coverage.out coverage.html

# Cross-compile for common targets
release:
	GOOS=linux   GOARCH=amd64  go build -o dist/$(BINARY)-linux-amd64   $(CMD_PATH)
	GOOS=linux   GOARCH=arm64  go build -o dist/$(BINARY)-linux-arm64   $(CMD_PATH)
	GOOS=darwin  GOARCH=amd64  go build -o dist/$(BINARY)-darwin-amd64  $(CMD_PATH)
	GOOS=darwin  GOARCH=arm64  go build -o dist/$(BINARY)-darwin-arm64  $(CMD_PATH)
	GOOS=windows GOARCH=amd64  go build -o dist/$(BINARY)-windows-amd64.exe $(CMD_PATH)
