# 🐳 CyberNox Docker Deployment Guide

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB+ available RAM
- 10GB+ available disk space

## 🚀 Quick Start

### 1. Basic Deployment
```bash
# Clone and navigate to project
cd "d:\Cyber lesson\python\CyberNox"

# Start CyberNox with default configuration
docker-compose up -d cybernox redis postgres

# Check status
docker-compose ps
```

### 2. Full Stack with Nginx
```bash
# Start with reverse proxy
docker-compose --profile with-nginx up -d

# Access via:
# - HTTP: http://localhost (redirects to HTTPS)
# - HTTPS: https://localhost (with self-signed cert)
```

### 3. Development Mode
```bash
# Start development environment with live reload
docker-compose --profile development up -d cybernox-dev redis postgres

# Access dev server: http://localhost:5001
```

### 4. Full Monitoring Stack
```bash
# Start with monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d

# Access:
# - Grafana: http://localhost:3000 (admin/cybernox-admin)
# - Prometheus: http://localhost:9090
```

## 🏗️ Build Options

### Production Build
```bash
# Build production image
docker build --target production -t cybernox:latest .

# Run standalone
docker run -d -p 5000:5000 --name cybernox cybernox:latest
```

### Development Build
```bash
# Build development image
docker build --target development -t cybernox:dev .

# Run with live reload
docker run -d -p 5000:5000 -v $(pwd):/app cybernox:dev
```

## 🌐 Service Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **CyberNox Web** | http://localhost:5000 | Main web interface |
| **CyberNox API** | http://localhost:5000/api/v1 | REST API endpoints |
| **Development** | http://localhost:5001 | Dev server with debug |
| **Nginx (HTTP)** | http://localhost | Reverse proxy |
| **Nginx (HTTPS)** | https://localhost | Secure reverse proxy |
| **Grafana** | http://localhost:3000 | Monitoring dashboard |
| **Prometheus** | http://localhost:9090 | Metrics collection |
| **PostgreSQL** | localhost:5432 | Database (cybernox/cybernox-secure-password) |
| **Redis** | localhost:6379 | Cache (password: cybernox-redis-pass) |

## 📊 Docker Compose Profiles

### Default Profile (Core Services)
```bash
docker-compose up -d
```
- ✅ CyberNox application
- ✅ Redis cache
- ✅ PostgreSQL database

### With Nginx Reverse Proxy
```bash
docker-compose --profile with-nginx up -d
```
- ✅ All core services
- ✅ Nginx reverse proxy with SSL
- ✅ Rate limiting and security headers

### Development Profile
```bash
docker-compose --profile development up -d
```
- ✅ Development server with live reload
- ✅ Debug mode enabled
- ✅ Code volume mounting

### Monitoring Profile
```bash
docker-compose --profile monitoring up -d
```
- ✅ Prometheus metrics collection
- ✅ Grafana visualization
- ✅ System monitoring

## 🔧 Configuration

### Environment Variables
Create `.env` file:
```env
# Application
CYBERNOX_ENV=production
FLASK_ENV=production
PYTHONPATH=/app

# Database
POSTGRES_DB=cybernox
POSTGRES_USER=cybernox
POSTGRES_PASSWORD=your-secure-password

# Redis
REDIS_PASSWORD=your-redis-password

# Security
SECRET_KEY=your-very-long-secret-key-change-this-in-production
```

### Custom Configuration
```bash
# Copy and modify config
cp config.yml config/custom-config.yml

# Mount custom config
docker-compose up -d -v ./config/custom-config.yml:/app/config.yml:ro
```

## 💾 Data Persistence

### Volumes
- `cybernox_reports`: Scan reports and outputs
- `cybernox_logs`: Application logs
- `cybernox_postgres_data`: Database data
- `cybernox_redis_data`: Cache data

### Backup Data
```bash
# Backup database
docker-compose exec postgres pg_dump -U cybernox cybernox > backup.sql

# Backup volumes
docker run --rm -v cybernox_reports:/data -v $(pwd):/backup alpine tar czf /backup/reports-backup.tar.gz /data
```

### Restore Data
```bash
# Restore database
docker-compose exec -T postgres psql -U cybernox cybernox < backup.sql

# Restore volumes
docker run --rm -v cybernox_reports:/data -v $(pwd):/backup alpine tar xzf /backup/reports-backup.tar.gz -C /
```

## 🛠️ Common Commands

### Service Management
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart cybernox

# View logs
docker-compose logs -f cybernox

# Scale services
docker-compose up -d --scale cybernox=3
```

### Development Commands
```bash
# Execute commands in container
docker-compose exec cybernox python main.py --help

# Access container shell
docker-compose exec cybernox bash

# Install additional packages
docker-compose exec cybernox pip install new-package
```

### Health Checks
```bash
# Check container health
docker-compose ps

# Check application health
curl http://localhost:5000/api/v1/status

# View resource usage
docker stats
```

## 🔒 Security Considerations

### Production Security
1. **Change default passwords** in `docker-compose.yml`
2. **Generate secure SSL certificates** for Nginx
3. **Configure firewall rules** for exposed ports
4. **Enable log monitoring** and alerting
5. **Regular security updates** for base images

### SSL Certificate Setup
```bash
# Generate self-signed certificate (development)
mkdir -p config/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout config/ssl/cybernox.key \
  -out config/ssl/cybernox.crt \
  -subj "/C=US/ST=State/L=City/O=CyberNox/CN=localhost"
```

### Network Security
```bash
# Create custom network with restricted access
docker network create --driver bridge \
  --subnet=172.25.0.0/16 \
  --ip-range=172.25.1.0/24 \
  cybernox-secure
```

## 🐛 Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Check what's using the port
netstat -tulpn | grep :5000
# or change port in docker-compose.yml
```

**Permission denied:**
```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./data ./reports ./logs
```

**Database connection failed:**
```bash
# Check database logs
docker-compose logs postgres

# Reset database
docker-compose down -v
docker-compose up -d postgres
```

**Out of memory:**
```bash
# Check resource usage
docker stats

# Increase memory limits in docker-compose.yml
services:
  cybernox:
    deploy:
      resources:
        limits:
          memory: 2G
```

### Debugging
```bash
# Enable debug mode
docker-compose exec cybernox python main.py serve --debug

# Check application logs
docker-compose logs -f cybernox | tail -100

# Interactive debugging
docker-compose run --rm cybernox python -c "import pdb; pdb.set_trace()"
```

## 📝 Maintenance

### Updates
```bash
# Pull latest images
docker-compose pull

# Rebuild with updates
docker-compose build --no-cache

# Restart with new images
docker-compose up -d --force-recreate
```

### Cleanup
```bash
# Remove unused containers and images
docker system prune -a

# Remove specific volumes (⚠️ DATA LOSS)
docker volume rm cybernox_reports cybernox_logs
```

## 🎯 Performance Tuning

### Resource Limits
```yaml
# In docker-compose.yml
services:
  cybernox:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

### Database Optimization
```yaml
postgres:
  environment:
    - POSTGRES_SHARED_PRELOAD_LIBRARIES=pg_stat_statements
    - POSTGRES_MAX_CONNECTIONS=200
    - POSTGRES_SHARED_BUFFERS=256MB
```

This Docker setup provides a professional, scalable deployment for your CyberNox cybersecurity toolkit! 🛡️
