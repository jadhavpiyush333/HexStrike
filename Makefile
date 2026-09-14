.PHONY: install test health doctor assess
install:
	python -m pip install -e .
test:
	pytest -q
health:
	python -m src.cli.main health
doctor:
	python -m src.cli.main doctor
assess:
	python -m src.cli.main assess $(TARGET)
