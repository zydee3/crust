.PHONY: all build release clean deps install uninstall restorer run

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

# Restorer paths
RESTORER_RS = src/restorer_blob.rs
RESTORER_GENERATED = crust-restorer/target/restorer_blob.rs

all: build

build: restorer
	cargo build

release: restorer
	cargo build --release

# Build the restorer blob (delegates to crust-restorer/Makefile)
restorer: $(RESTORER_RS)

$(RESTORER_RS): crust-restorer/src/lib.rs crust-restorer/Cargo.toml crust-syscall/src/*.rs
	@echo "=== Building restorer blob (delegating to crust-restorer) ==="
	@$(MAKE) -C crust-restorer
	@cp $(RESTORER_GENERATED) $(RESTORER_RS)
	@echo "[OK] Copied $(RESTORER_GENERATED) -> $(RESTORER_RS)"

clean:
	cargo clean
	@$(MAKE) -C crust-restorer clean
	@rm -f $(RESTORER_RS)
	@echo "Cleaned all build artifacts"

deps:
	@echo "Installing system dependencies (requires sudo)..."
	sudo apt-get update
	sudo apt-get install -y protobuf-compiler libprotobuf-dev

install: release
	@echo "Installing crust to $(BINDIR)..."
	install -D -m 755 target/release/crust $(BINDIR)/crust
	@echo "running 'install -D -m 755 target/release/crust $(BINDIR)/crust'"
	@echo "crust installed successfully. Run 'crust --help' to get started."

uninstall:
	@echo "Removing crust from $(BINDIR)..."
	rm -f $(BINDIR)/crust
	@echo "crust uninstalled."

run: build
	bash test/restore.sh