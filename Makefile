.PHONY: install install-prod dev test lint run worker worker-once seed build frontend-install frontend-test frontend-build check compose lock openapi clean

install:
	python -m pip install -e .

install-prod:
	python -m pip install --require-hashes -r requirements-production.lock
	python -m pip install --no-deps -e .

dev:
	python -m pip install -e '.[dev]'

test:
	python -m pytest

lint:
	python -m ruff check fraudshield tests

run:
	fraudshield serve --host 127.0.0.1 --port 8000

worker:
	fraudshield worker

worker-once:
	fraudshield worker --once

seed:
	python scripts/seed_demo.py

build:
	python -m build --no-isolation

frontend-install:
	cd frontend && npm ci --ignore-scripts --no-audit --no-fund

frontend-test:
	cd frontend && npm test

frontend-build:
	cd frontend && npm run check

check: lint test frontend-test

compose:
	docker compose up --build

lock:
	python -m piptools compile pyproject.toml --extra production --generate-hashes --strip-extras --resolver backtracking --no-emit-index-url --no-emit-trusted-host --output-file requirements-production.lock
	python -m piptools compile requirements-build.in --generate-hashes --strip-extras --resolver backtracking --allow-unsafe --no-emit-index-url --no-emit-trusted-host --output-file requirements-build.lock

openapi:
	python -c "import json; from pathlib import Path; from fraudshield.main import create_app; Path('docs/openapi.json').write_text(json.dumps(create_app().openapi(), indent=2) + '\\n', encoding='utf-8')"

clean:
	python -c "from pathlib import Path; [p.unlink() for p in Path('.').rglob('*.pyc')]"
