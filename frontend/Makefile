.PHONY: install run dev server build clean help

# Default target - run both frontend and server
run: install
	npm run dev:all

# Install all dependencies
install:
	@if [ ! -d "node_modules" ]; then \
		echo "Installing dependencies..."; \
		npm install; \
	fi

# Run only the Vite dev server (frontend)
dev: install
	npm run dev

# Run only the mock API server
server: install
	npm run server

# Build for production
build: install
	npm run build

# Clean up node_modules and build artifacts
clean:
	rm -rf node_modules
	rm -rf dist
	rm -rf server/node_modules

# Show available commands
help:
	@echo "Available commands:"
	@echo "  make run     - Install deps and run both frontend & server (default)"
	@echo "  make dev     - Run only the Vite dev server"
	@echo "  make server  - Run only the mock API server"
	@echo "  make build   - Build for production"
	@echo "  make install - Install dependencies"
	@echo "  make clean   - Remove node_modules and build artifacts"
	@echo "  make help    - Show this help message"
