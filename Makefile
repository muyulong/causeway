BIN_DIR := bin
export GOFLAGS := -buildvcs=false
export CGO_ENABLED := 0

.PHONY: all build agent relay test clean

all: build

build: agent relay

agent:
	go build -o $(BIN_DIR)/agent ./cmd/agent

relay:
	go build -o $(BIN_DIR)/relay ./cmd/relay

test:
	go test ./...

clean:
	rm -rf $(BIN_DIR)
