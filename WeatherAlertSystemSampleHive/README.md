# Weather Alert System — Hive Framework Sample

A compilable, runnable example demonstrating the **Cilium Hive** dependency injection framework with 5 interconnected cells in a modular package structure.

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Sensor Cell │────►│  Store Cell  │────►│  Alert Cell  │────►│  Notify Cell │
│  (auto-poll) │     │  (in-memory) │     │  (threshold) │     │  (console)   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            ▲
┌──────────────┐            │
│   API Cell   │────────────┘
│  (HTTP :8080)│  ← You POST readings here
└──────────────┘
```

**Data flows:**
- **Sensor Cell** (`pkg/sensor`) — auto-generates random weather readings on a timer → pushes to Store
- **API Cell** (`pkg/api`) — exposes HTTP endpoints so YOU can inject custom readings → pushes to Store
- **Store Cell** (`pkg/store`) — holds all readings in-memory and notifies subscribers
- **Alert Cell** (`pkg/alert`) — watches Store, evaluates thresholds, fires alerts → sends to Notify
- **Notify Cell** (`pkg/notify`) — formats and outputs alerts to console (or simulated email)
- **Model** (`pkg/model`) — shared types (`WeatherReading`, `Alert`) used across all cells

---

## Project Structure

```
WeatherAlertSystemSampleHive/
├── cmd/
│   └── weather-alert/
│       └── main.go          # Composition root — wires all cells into a Hive
├── pkg/
│   ├── model/
│   │   └── model.go         # Shared types: WeatherReading, Alert
│   ├── store/
│   │   └── store.go         # Cell 1: In-memory data store
│   ├── sensor/
│   │   └── sensor.go        # Cell 2: Periodic weather data generator
│   ├── alert/
│   │   └── alert.go         # Cell 3: Threshold evaluator
│   ├── notify/
│   │   └── notify.go        # Cell 4: Alert dispatcher (console/email)
│   └── api/
│       └── api.go           # Cell 5: HTTP API for external injection
├── go.mod
├── go.sum
└── README.md
```

---

## Prerequisites

- Go 1.21+ installed
- No other services needed — this is a **self-contained, single-binary** application

---

## Build

```powershell
cd WeatherAlertSystemSampleHive
go mod tidy
go build ./cmd/weather-alert
```

This produces `weather-alert.exe` (Windows) or `weather-alert` (Linux/Mac).

---

## Run the Service

```powershell
# Basic (uses all defaults: poll every 3s, threshold 35°C, API on :8080)
.\weather-alert.exe

# With custom settings (more frequent polling, lower threshold = more alerts)
.\weather-alert.exe --sensor-poll-interval=2s --alert-temp-threshold=25.0 --api-listen-addr=:8080
```

The service starts and does **two things simultaneously**:
1. **Auto-generates** random weather data every N seconds (Sensor Cell)
2. **Listens on HTTP** for you to inject custom readings (API Cell)

Press `Ctrl+C` to stop gracefully.

---

## Do I Need Another Service?

**No.** This is fully self-contained. The Sensor Cell auto-generates test data, so you'll see output immediately. However, the **API Cell** lets you inject your own data if you want to test specific scenarios (e.g., extreme heat, high wind).

---

## Feeding Custom Values via HTTP API

While the service is running, open **another terminal** and use `curl` (or Postman/Invoke-WebRequest):

### Inject a weather reading (triggers alert evaluation)

```powershell
# POST a hot reading — this will trigger a HEAT alert if temp > threshold
curl -X POST http://localhost:8080/reading `
  -H "Content-Type: application/json" `
  -d '{"temperature": 42.5, "humidity": 15.0, "wind_speed": 90.0, "location": "Mumbai"}'
```

**Request body fields:**
| Field | Type | Description |
|-------|------|-------------|
| `temperature` | float | Temperature in °C |
| `humidity` | float | Humidity percentage (0-100) |
| `wind_speed` | float | Wind speed in km/h |
| `location` | string | Station name (optional, defaults to "External") |

**Response:**
```json
{"status": "accepted", "message": "Reading recorded: 42.5°C, 15.0% humidity, 90.0 km/h wind"}
```

### Get all stored readings

```powershell
curl http://localhost:8080/readings
```

**Response:**
```json
{
  "count": 5,
  "readings": [
    {"temperature": 28.3, "humidity": 55.2, "wind_speed": 42.9, "location": "Seattle", "timestamp": "..."},
    {"temperature": 42.5, "humidity": 15.0, "wind_speed": 90.0, "location": "Mumbai", "timestamp": "..."}
  ]
}
```

### Health check

```powershell
curl http://localhost:8080/health
# {"status":"ok","time":"2026-06-10T15:25:07+05:30"}
```

---

## Example: Triggering Different Alert Types

```powershell
# Start with low thresholds to see alerts easily
.\weather-alert.exe --alert-temp-threshold=25 --alert-wind-threshold=50 --sensor-poll-interval=10s

# In another terminal:

# 1. Trigger a HEAT alert (temp > 25°C)
curl -X POST http://localhost:8080/reading -H "Content-Type: application/json" -d '{"temperature": 38.0, "humidity": 40.0, "wind_speed": 10.0, "location": "Delhi"}'

# 2. Trigger a WIND alert (wind > 50 km/h)
curl -X POST http://localhost:8080/reading -H "Content-Type: application/json" -d '{"temperature": 20.0, "humidity": 60.0, "wind_speed": 85.0, "location": "Chicago"}'

# 3. Normal reading (no alert)
curl -X POST http://localhost:8080/reading -H "Content-Type: application/json" -d '{"temperature": 22.0, "humidity": 55.0, "wind_speed": 30.0, "location": "Seattle"}'
```

---

## All Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--sensor-poll-interval` | `3s` | How often the sensor auto-generates readings |
| `--sensor-location` | `Seattle` | Auto-generated reading location name |
| `--store-max-readings` | `100` | Max readings kept in memory (oldest dropped) |
| `--alert-temp-threshold` | `35.0` | Temperature (°C) that triggers CRITICAL alert |
| `--alert-wind-threshold` | `80.0` | Wind speed (km/h) that triggers WARNING alert |
| `--notify-channel` | `console` | Alert output: `console` or `email` (simulated) |
| `--notify-recipient` | `admin@example.com` | Email recipient (for email channel) |
| `--api-listen-addr` | `:8080` | HTTP API listen address |

---

## What to Observe

1. **Automatic data flow** — Sensor readings appear every N seconds with random values
2. **Alert triggering** — When temp/wind exceed thresholds, you see `🚨 ALERT` boxes
3. **API injection** — POST a reading and watch it instantly flow through Alert → Notify
4. **Startup order** — Hive starts cells in dependency order (Store first, then consumers)
5. **Graceful shutdown** — Press Ctrl+C to see cells stop in reverse dependency order
6. **DI wiring** — Cells never import each other directly; only via the shared `pkg/model` types and DI

---

## Key Hive Patterns Demonstrated

| Pattern | Where | File |
|---------|-------|------|
| `cell.Module()` | Each cell definition | `pkg/*/_.go` |
| `cell.Provide()` | Registering constructors | All cell files |
| `cell.Invoke()` | Forcing leaf-cell instantiation | `sensor.go`, `alert.go`, `api.go` |
| `cell.Config()` + `Flags()` | Declarative configuration | All cell files |
| `cell.Lifecycle` + `cell.Hook` | Start/stop hooks | `sensor.go`, `alert.go`, `api.go` |
| `cell.In` params struct | Declaring DI dependencies | All cell files |
| `hive.New()` + `h.Run()` | Composing cells | `cmd/weather-alert/main.go` |
| `h.RegisterFlags()` | Exposing configs as CLI flags | `cmd/weather-alert/main.go` |

---

## Modularity: Why Separate Packages?

| Benefit | How |
|---------|-----|
| **Independent development** | Each cell is a self-contained package — add features without touching others |
| **Testability** | Mock `*store.Store` to unit-test `alert` or `api` in isolation |
| **Clear dependencies** | Import graph shows exactly which cells depend on what |
| **Reusability** | Drop `pkg/notify` into another project as-is |
| **Parallel builds** | Go compiles packages in parallel — faster builds |
| **Real-world pattern** | Mirrors how Cilium organizes its cells (`pkg/loadbalancer/`, `pkg/k8s/`, etc.) |

---

## Dependency Graph (Import-based)

```
cmd/weather-alert/main.go
  ├── pkg/store     (no internal deps)
  ├── pkg/notify    (imports pkg/model)
  ├── pkg/sensor    (imports pkg/model, pkg/store)
  ├── pkg/alert     (imports pkg/model, pkg/store, pkg/notify)
  └── pkg/api       (imports pkg/model, pkg/store)
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 8080 already in use | Use `--api-listen-addr=:9090` |
| No alerts appearing | Lower threshold: `--alert-temp-threshold=20` |
| Too many alerts | Raise threshold or increase poll interval |
| Build fails | Run `go mod tidy` first |
| `go build` without output | Use `go build ./cmd/weather-alert` (not `go build .`) |


