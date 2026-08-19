# Real-Time Threat Detection MVP

This repository contains an MVP scaffold for a real-time threat detection system using behavioural analysis.

- Gateway (Go): inline enforcement plane that validates JSON, checks a Redis blocklist, and emits telemetry to a Redis Stream.
- Processor (Python): out-of-band consumer that reads the telemetry stream, computes simple features, runs an Isolation Forest, and writes blocklist tokens to Redis.
- Redis: in-memory message broker and shared state store.

Quick start:

```bash
docker compose up --build
```

Send a test request:

```bash
curl -X POST http://localhost:8080/test -H "Content-Type: application/json" -H "X-User-ID: alice" -d '{"user_id":"alice","foo":"bar"}'
```

Files of interest:
- `gateway/main.go`
- `processor/app.py`
- `docker-compose.yml`

Pretrain model (optional, recommended for realistic behavior):

1. Create a Python virtualenv and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r processor/requirements.txt
```

2. Train a model using the sample dataset:

```bash
python processor/train.py --input data/sample_dataset.csv --output processor/model.pkl
```

3. Rebuild and run the services so the processor image includes the pretrained model (or mount the model into the container):

```bash
docker compose up --build
```

