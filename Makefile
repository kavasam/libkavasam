CLEAN_UP = target

default: frontend ## Build app in debug mode
	cargo build

clean: ## Delete build artifacts
	@cargo clean
	@-rm -rf $(CLEAN_UP)

coverage: ## Generate code coverage report in HTML format
	cargo tarpaulin -t 1200 --out Html

doc: ## Generate documentation
	cargo doc --no-deps --workspace --all-features

env: ## Setup development environtment
	cargo fetch

lint: ## Lint codebase
	cargo fmt -v --all -- --emit files
	cargo clippy --workspace --tests --all-features

release: ## Build app with release optimizations
	cargo build --release

test: ## Run all available tests
	cargo test --all-features --no-fail-fast

xml-test-coverage: ## Generate code coverage report in XML format
	cargo tarpaulin -t 1200 --out Xml

help: ## Prints help for targets with comments
	@cat $(MAKEFILE_LIST) | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
