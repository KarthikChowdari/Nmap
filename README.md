# Go Port Scanner 🔍

A high-performance concurrent port scanner written in Go with HTTP banner grabbing.

## Features
- Concurrent port scanning using goroutines
- Worker pool architecture
- CLI flags for host, port range, and worker count
- Real-time scan progress tracking
- TCP banner grabbing
- HTTP protocol-aware probing with resilient banner parsing
- Optional JSON report export

## Usage
```bash
go run main.go -host scanme.nmap.org
```

### Common Examples

Scan a custom range with custom concurrency:

```bash
go run main.go -host example.com -start 1 -end 5000 -workers 100
```

Save open-port results to JSON:

```bash
go run main.go -host example.com -start 1 -end 1024 -workers 75 -json results.json
```

### Flags

```text
-host     Target host or IP (required)
-start    Start port (default: 1)
-end      End port (default: 1024)
-workers  Number of worker goroutines (default: 50)
-json     Optional path to save report as JSON
```
