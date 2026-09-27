.PHONY: test test-policy test-python gen gen-check demo checks-doc fixtures

test: test-policy test-python gen-check

test-policy:
	opa check --strict policy/
	opa test policy/ --ignore '*.yaml'
	policy/ci/check.sh
	@if command -v kyverno >/dev/null; then policy/admission/kyverno/check.sh; else echo "SKIP kyverno CLI not found"; fi

test-python:
	python -m pytest -q

gen:
	membrane gen

gen-check:
	membrane gen --check

demo:
	scripts/demo.sh

checks-doc:
	membrane checks doc

fixtures:
	python fixtures/build_fixtures.py
