# Paths
DIST_DIR := dist
DOCS_DIR := ../docs

.PHONY: all build deploy clean

all: deploy

# Build the release WASM bundle using Trunk
build:
	trunk build --release

# Sync the build artifacts to the root docs/ folder for GitHub Pages
deploy: build
	rm -rf $(DOCS_DIR)
	mkdir -p $(DOCS_DIR)
	cp -r $(DIST_DIR)/* $(DOCS_DIR)/
	@echo "Deployment assets synced to $(DOCS_DIR)"

# Clean build artifacts
clean:
	rm -rf $(DIST_DIR)
	rm -rf target
