.PHONY: install scan gate baseline test lint clean demo

install:
	pip install -e ".[all,dev]"

scan:
	threatforge scan . -v

gate:
	threatforge gate .

baseline:
	threatforge baseline .

demo:
	threatforge scan tests/fixtures/vulnerable -o /tmp/tf-demo -v
	@echo "open /tmp/tf-demo/security-report.html"

test:
	pytest -q

clean:
	rm -rf threatforge-out .pytest_cache **/__pycache__ dist build *.egg-info
