BIN_DIR := bin
PREFIX ?= $(HOME)/.local
HERMES_MANIFEST := tools/hermes-diff/Cargo.toml
HERMES_BIN := tools/hermes-diff/target/release/hermes-diff

.PHONY: build build-go build-hermes install uninstall test test-go test-hermes clean

build: build-go build-hermes

build-go:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/ipadiff ./cmd/ipadiff

build-hermes:
	cargo build --release --manifest-path $(HERMES_MANIFEST)
	mkdir -p $(BIN_DIR)
	cp $(HERMES_BIN) $(BIN_DIR)/hermes-diff

install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BIN_DIR)/ipadiff $(PREFIX)/bin/ipadiff
	install -m 0755 $(BIN_DIR)/hermes-diff $(PREFIX)/bin/hermes-diff

uninstall:
	rm -f $(PREFIX)/bin/ipadiff $(PREFIX)/bin/hermes-diff

test: test-go test-hermes

test-go:
	go test ./...

test-hermes:
	cargo test --manifest-path $(HERMES_MANIFEST)

clean:
	rm -rf $(BIN_DIR)
	cargo clean --manifest-path $(HERMES_MANIFEST)
