.PHONY: install test lint format run docker clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -r requirements.txt

install-dev: ## Install dev dependencies
	pip install -r requirements.txt
	pip install pytest black ruff mypy

test: ## Run tests
	python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage
	python -m pytest tests/ -v --cov=core --cov-report=html --cov-report=term

lint: ## Run linter
	ruff check core/ cli/ api/ tests/

format: ## Format code
	black core/ cli/ api/ tests/

run: ## Start API server
	python -m api.server

validate: ## Validate all templates
	@for f in templates/**/*.yaml; do echo "Validating $$f..."; python -m cli.main validate $$f; done

scan: ## Security scan all templates
	@for f in templates/**/*.yaml; do echo "Scanning $$f..."; python -m cli.main scan $$f; done

docker: ## Build Docker image
	docker-compose build

docker-up: ## Start Docker containers
	docker-compose up -d

docker-down: ## Stop Docker containers
	docker-compose down

clean: ## Clean build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage dist build *.egg-info

version: ## Show version
	python -m cli.main version
