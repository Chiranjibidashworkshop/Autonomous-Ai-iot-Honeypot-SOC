PYTHON ?= python3

install:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt

train:
	. .venv/bin/activate && $(PYTHON) scripts/train_model.py

run:
	. .venv/bin/activate && $(PYTHON) -m src.iot_honeypot.main

dashboard:
	. .venv/bin/activate && streamlit run src/soc_dashboard/app.py

test:
	. .venv/bin/activate && python -m pytest -q
