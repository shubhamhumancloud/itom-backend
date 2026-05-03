BINARY  := itom-agent
VERSION ?= 0.1.0
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"
DIST    := dist

.PHONY: all build build-all clean run tidy

all: build

tidy:
	go mod tidy

# Build for the current platform
build: tidy
	mkdir -p $(DIST)
	go build $(LDFLAGS) -o $(DIST)/$(BINARY) ./cmd/agentd

# Build static binaries for the platforms you'll deploy to
build-all: tidy
	mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64       ./cmd/agentd
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-arm64       ./cmd/agentd
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-arm64      ./cmd/agentd
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-amd64      ./cmd/agentd
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe ./cmd/agentd

run: build
	./$(DIST)/$(BINARY)

clean:
	rm -rf $(DIST)
