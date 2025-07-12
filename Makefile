# CyberNox Docker Management
# Simple commands for Docker operations

.PHONY: help build up down logs shell clean backup restore

# Default target
help:
	@echo "🐳 CyberNox Docker Commands"
	@echo ""
	@echo "Basic Operations:"
	@echo "  make build     - Build Docker images"
	@echo "  make up        - Start all services"
	@echo "  make down      - Stop all services"
	@echo "  make logs      - View application logs"
	@echo "  make shell     - Access container shell"
	@echo ""
	@echo "Development:"
	@echo "  make dev       - Start development environment"
	@echo "  make dev-logs  - View development logs"
	@echo ""
	@echo "Production:"
	@echo "  make prod      - Start production environment"
	@echo "  make nginx     - Start with Nginx reverse proxy"
	@echo "  make monitor   - Start with monitoring stack"
	@echo ""
	@echo "Maintenance:"
	@echo "  make backup    - Backup data volumes"
	@echo "  make restore   - Restore data volumes"
	@echo "  make clean     - Clean up Docker resources"
	@echo "  make update    - Update and restart services"

# Build images
build:
	@echo "🔨 Building CyberNox Docker images..."
	docker-compose build

# Start core services
up:
	@echo "🚀 Starting CyberNox services..."
	docker-compose up -d cybernox redis postgres
	@echo "✅ Services started! Access: http://localhost:5000"

# Stop all services
down:
	@echo "🛑 Stopping CyberNox services..."
	docker-compose down

# View logs
logs:
	@echo "📋 Viewing CyberNox logs..."
	docker-compose logs -f cybernox

# Access container shell
shell:
	@echo "🐚 Accessing CyberNox container..."
	docker-compose exec cybernox bash

# Development environment
dev:
	@echo "🛠️ Starting development environment..."
	docker-compose --profile development up -d
	@echo "✅ Development server started! Access: http://localhost:5001"

dev-logs:
	@echo "📋 Viewing development logs..."
	docker-compose logs -f cybernox-dev

# Production environment
prod:
	@echo "🏭 Starting production environment..."
	docker-compose up -d cybernox redis postgres
	@echo "✅ Production server started! Access: http://localhost:5000"

# Start with Nginx
nginx:
	@echo "🌐 Starting with Nginx reverse proxy..."
	docker-compose --profile with-nginx up -d
	@echo "✅ Services with Nginx started!"
	@echo "   HTTP:  http://localhost"
	@echo "   HTTPS: https://localhost"

# Start monitoring stack
monitor:
	@echo "📊 Starting monitoring stack..."
	docker-compose --profile monitoring up -d
	@echo "✅ Monitoring stack started!"
	@echo "   CyberNox: http://localhost:5000"
	@echo "   Grafana:  http://localhost:3000 (admin/cybernox-admin)"
	@echo "   Prometheus: http://localhost:9090"

# Backup data
backup:
	@echo "💾 Creating backup..."
	mkdir -p backups
	docker-compose exec postgres pg_dump -U cybernox cybernox > backups/database-$(shell date +%Y%m%d-%H%M%S).sql
	docker run --rm -v cybernox_reports:/data -v $(PWD)/backups:/backup alpine tar czf /backup/reports-$(shell date +%Y%m%d-%H%M%S).tar.gz /data
	@echo "✅ Backup completed in ./backups/"

# Restore from backup (latest)
restore:
	@echo "🔄 Restoring from latest backup..."
	@ls -la backups/
	@echo "⚠️  Make sure to specify the correct backup file!"

# Clean up Docker resources
clean:
	@echo "🧹 Cleaning up Docker resources..."
	docker-compose down -v
	docker system prune -f
	docker volume prune -f
	@echo "✅ Cleanup completed!"

# Update and restart
update:
	@echo "🔄 Updating CyberNox..."
	docker-compose pull
	docker-compose build --no-cache
	docker-compose up -d --force-recreate
	@echo "✅ Update completed!"

# Quick status check
status:
	@echo "📊 CyberNox Service Status:"
	docker-compose ps
	@echo ""
	@echo "💾 Volume Usage:"
	docker volume ls | grep cybernox
	@echo ""
	@echo "🌐 Network Status:"
	docker network ls | grep cybernox

# Health check
health:
	@echo "🏥 Checking CyberNox health..."
	@curl -s http://localhost:5000/api/v1/status | python -m json.tool || echo "❌ API not responding"
	@echo ""
	@docker-compose exec cybernox python main.py health || echo "❌ Health check failed"
