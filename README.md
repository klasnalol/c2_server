# C2 Server + Separate AI Detection Backend

This repository now runs with two independent apps:

- `c2_server.py`: ingestion, logging, dashboard, manual labeling
- `ai_detection_backend.py`: AI analysis service (model-backed, HTTP API)

The C2 server calls the AI backend at `ai_backend_url` from `c2_config.json`.

## 1. Start Services

Start AI backend first:

```bash
bash manage.sh ai-start
```

Check AI backend status:

```bash
bash manage.sh ai-status
```

Start C2 server:

```bash
bash manage.sh start
```

## 2. AI Backend Configuration

Edit `ai_backend_config.json`:

- `provider`: currently `ollama`
- `model`: example `llama3.1:8b`
- `ollama_url`: usually `http://127.0.0.1:11434/api/generate`
- `request_timeout_seconds`

The backend endpoint is:

- `POST /analyze` (port 8090 by default)

Payload:

```json
{
  "event_id": "uuid-or-any-id",
  "text": "candidate payload text"
}
```

Response:

```json
{
  "event_id": "uuid-or-any-id",
  "result": {
    "detected": true,
    "score": 0.91,
    "reasons": ["..."],
    "techniques": ["T1059.001"],
    "provider": "ollama",
    "model": "llama3.1:8b",
    "mode": "model"
  }
}
```

If model inference fails, backend returns `mode: fallback` with heuristic scoring.

## 3. C2 Configuration

In `c2_config.json`, you can set:

```json
{
  "c2_port": 8080,
  "ai_backend_url": "http://127.0.0.1:8090/analyze",
  "ai_backend_timeout_seconds": 8
}
```

## 4. Manual Ground Truth (Volatility / IR)

Manual verdicts can be attached via:

- `POST /manual/label`

Example:

```json
{
  "event_id": "<event_id_from_collect>",
  "detected": true,
  "tool": "volatility",
  "techniques": ["T1059.001"],
  "notes": "confirmed in memory artifacts"
}
```

Or import a file:

```bash
bash manage.sh import-manual /path/to/manual_labels.json
```

The dashboard/API will compare manual vs AI using those labels.

## 5. Stop Services

```bash
bash manage.sh stop
bash manage.sh ai-stop
```

## 6. Remote GPU Deployment (Recommended)

If your C2 host is weak, run only `c2_server.py` there and run `ai_detection_backend.py`
on a separate GPU machine.

### On the GPU machine

1. Install Ollama and pull model:

```bash
ollama pull llama3.1:8b
```

2. Start Ollama service and verify API is reachable on port `11434`.

3. In this repo, set `ai_backend_config.json` and start backend:

```bash
bash manage.sh ai-start
```

4. Open backend port `8090` on firewall for your C2 host only.

### On the C2 host

Set remote backend URL in `c2_config.json`:

```json
{
  "c2_port": 8080,
  "host_ip": "192.168.8.90",
  "ai_backend_url": "http://<GPU_HOST_IP>:8090/analyze",
  "ai_backend_timeout_seconds": 12
}
```

Then run only:

```bash
bash manage.sh start
```

No AI model loads on the C2 server in this design. The C2 host only performs a
small HTTP call to the AI backend.

### Hardening tips

- Restrict `8090` to C2 source IPs with firewall rules.
- Place backend behind reverse proxy with API key if used outside trusted LAN.
- Keep `request_timeout_seconds` low to avoid blocking C2 ingestion.