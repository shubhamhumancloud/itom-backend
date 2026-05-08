BINARY  := itom-agent
VERSION ?= 0.4.0
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"
DIST    := dist

# Backend serves the patcher templates from this folder. Every "build-all"
# invocation refreshes them — there are no per-tenant prebuilt binaries; the
# backend patches a fresh copy of the template at install-request time.
BE_TEMPLATES := ../BE/agents-dist/templates

.PHONY: all build build-all clean run tidy

all: build

tidy:
	go mod tidy

# Build for the current platform (useful for dev / agent-side iteration)
build: tidy
	mkdir -p $(DIST)
	go build $(LDFLAGS) -o $(DIST)/$(BINARY) ./cmd/agentd

# Build patcher templates for every supported platform and copy them into
# BE/agents-dist/templates/.
#
# These binaries contain the literal placeholder strings
# "ITOMBAKED_TENANT_ID:..." and "ITOMBAKED_SERVER_URL:..." — the backend's
# BinaryPatcherService finds and overwrites them per request.
build-all: tidy
	mkdir -p $(DIST) $(BE_TEMPLATES)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64       ./cmd/agentd
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-arm64       ./cmd/agentd
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-arm64      ./cmd/agentd
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-amd64      ./cmd/agentd
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe ./cmd/agentd
	cp $(DIST)/$(BINARY)-* $(BE_TEMPLATES)/
	@echo "Templates published to $(BE_TEMPLATES)/"

run: build
	./$(DIST)/$(BINARY) run

clean:
	rm -rf $(DIST) $(BE_TEMPLATES)
