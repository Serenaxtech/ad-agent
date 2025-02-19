poetry add --dev pytest black mypy

# tests
poetry run pytest --cov=my_package --cov-report=term-missing

# docs
poetry run sphinx-apidoc -o docs/source src/
poetry run make -C docs html