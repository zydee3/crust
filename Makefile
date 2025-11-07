.PHONY: all build release clean deps install uninstall

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

all: build

build:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

deps:
	@echo "Installing system dependencies (requires sudo)..."
	sudo apt-get update
	sudo apt-get install -y protobuf-compiler libprotobuf-dev

install: release
	@echo "Installing crust to $(BINDIR)..."
	install -D -m 755 target/release/crust $(BINDIR)/crust
	@echo "crust installed successfully. Run 'crust --help' to get started."

uninstall:
	@echo "Removing crust from $(BINDIR)..."
	rm -f $(BINDIR)/crust
	@echo "crust uninstalled."

run:
	bash test/restore.sh