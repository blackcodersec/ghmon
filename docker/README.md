# Docker Deployment Guide for ghmon-cli

This guide covers containerized deployment of ghmon-cli for production environments, CI/CD pipelines, and scalable monitoring setups.

## Quick Start

### 1. Basic Setup

```bash
# Clone the repository
git clone https://github.com/sl4x0/ghmon.git
cd ghmon

# Configure your settings
cp ghmon_config.yaml.example ghmon_config.yaml
# Edit ghmon_config.yaml with your API tokens and notification settings

# Build the image
docker build -t ghmon-cli:latest .
```

### 2. One-time Scan

```bash
docker run --rm \
  -v $(pwd)/ghmon_config.yaml:/app/ghmon_config.yaml:ro \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  ghmon-cli:latest \
  python -m ghmon_cli scan -o YOUR_ORG_NAME --config /app/ghmon_config.yaml
```

### 3. Continuous Monitoring

```bash
docker run -d \
  --name ghmon-monitor \
  --restart unless-stopped \
  -v $(pwd)/ghmon_config.yaml:/app/ghmon_config.yaml:ro \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  ghmon-cli:latest \
  python -m ghmon_cli monitor --config /app/ghmon_config.yaml
```

## Docker Compose (Recommended)

### Basic Monitoring Service

```bash
# Start continuous monitoring
docker-compose up -d

# View logs
docker-compose logs -f ghmon-cli

# Stop service
docker-compose down
```

### One-time Scan

```bash
# Run scan for specific organization
ORG_NAME=your-org-name docker-compose --profile scan up ghmon-scan

# Run scan with custom command
docker-compose run --rm ghmon-scan python -m ghmon_cli scan -o myorg --config /app/ghmon_config.yaml
```

## Advanced Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHMON_CONFIG_PATH` | Path to configuration file | `/app/ghmon_config.yaml` |
| `GHMON_DATA_DIR` | Data persistence directory | `/app/data` |
| `GHMON_LOG_DIR` | Log output directory | `/app/logs` |
| `PYTHONUNBUFFERED` | Disable Python output buffering | `1` |

### Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./ghmon_config.yaml` | `/app/ghmon_config.yaml` | Configuration (read-only) |
| `./data` | `/app/data` | State and scan results |
| `./logs` | `/app/logs` | Application logs |

### Resource Limits

```yaml
# In docker-compose.yml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.5'
    reservations:
      memory: 256M
      cpus: '0.25'
```

## Production Deployment

### 1. Multi-Organization Setup

```bash
# Create separate containers for different organizations
docker run -d \
  --name ghmon-org1 \
  -v $(pwd)/config-org1.yaml:/app/ghmon_config.yaml:ro \
  -v $(pwd)/data-org1:/app/data \
  -v $(pwd)/logs-org1:/app/logs \
  ghmon-cli:latest \
  python -m ghmon_cli monitor --config /app/ghmon_config.yaml

docker run -d \
  --name ghmon-org2 \
  -v $(pwd)/config-org2.yaml:/app/ghmon_config.yaml:ro \
  -v $(pwd)/data-org2:/app/data \
  -v $(pwd)/logs-org2:/app/logs \
  ghmon-cli:latest \
  python -m ghmon_cli monitor --config /app/ghmon_config.yaml
```

### 2. Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghmon-cli
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ghmon-cli
  template:
    metadata:
      labels:
        app: ghmon-cli
    spec:
      containers:
      - name: ghmon-cli
        image: ghmon-cli:latest
        command: ["python", "-m", "ghmon_cli", "monitor", "--config", "/app/ghmon_config.yaml"]
        volumeMounts:
        - name: config
          mountPath: /app/ghmon_config.yaml
          subPath: ghmon_config.yaml
        - name: data
          mountPath: /app/data
        - name: logs
          mountPath: /app/logs
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
      volumes:
      - name: config
        configMap:
          name: ghmon-config
      - name: data
        persistentVolumeClaim:
          claimName: ghmon-data
      - name: logs
        persistentVolumeClaim:
          claimName: ghmon-logs
```

### 3. CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Repository Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run ghmon-cli scan
      run: |
        docker run --rm \
          -e GITHUB_TOKEN="${{ secrets.GITHUB_TOKEN }}" \
          -e DISCORD_WEBHOOK="${{ secrets.DISCORD_WEBHOOK }}" \
          -v ${{ github.workspace }}/ci-config.yaml:/app/ghmon_config.yaml:ro \
          ghmon-cli:latest \
          python -m ghmon_cli scan -o ${{ github.repository_owner }} --config /app/ghmon_config.yaml
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Ensure proper file permissions
   chmod 644 ghmon_config.yaml
   chmod 755 data logs
   ```

2. **Configuration Not Found**
   ```bash
   # Verify volume mount
   docker run --rm -v $(pwd)/ghmon_config.yaml:/app/ghmon_config.yaml:ro ghmon-cli:latest ls -la /app/
   ```

3. **TruffleHog Not Found**
   ```bash
   # Verify TruffleHog installation in container
   docker run --rm ghmon-cli:latest trufflehog --version
   ```

### Health Checks

```bash
# Check container health
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# View health check logs
docker inspect ghmon-monitor | jq '.[0].State.Health'

# Manual health check
docker exec ghmon-monitor python -m ghmon_cli --version
```

### Log Analysis

```bash
# Follow logs in real-time
docker-compose logs -f

# View specific service logs
docker logs ghmon-monitor

# Export logs for analysis
docker logs ghmon-monitor > ghmon-$(date +%Y%m%d).log
```

## Security Considerations

- **Non-root user**: Container runs as `ghmon` user (UID 1000)
- **Read-only config**: Configuration mounted as read-only
- **Network isolation**: No exposed ports by default
- **Resource limits**: CPU and memory constraints applied
- **Secret management**: Use Docker secrets or environment variables for sensitive data

## Performance Tuning

- **Memory**: Adjust based on organization size (256MB-1GB)
- **CPU**: Scale with scan frequency (0.25-1.0 cores)
- **Storage**: Ensure adequate space for logs and state files
- **Network**: Consider rate limiting for API calls
