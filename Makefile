SHELL := /usr/bin/env bash
COMPOSE ?= docker compose
BASE_URL ?= http://localhost:8000
ADMIN_TOKEN ?= $(shell grep -E '^ADMIN_TOKEN=' .env 2>/dev/null | cut -d= -f2-)

.PHONY: help init secrets build up down restart logs ps shell smoke backup restore clean

help:
	@echo "Targets:"
	@echo "  make init        Prépare .env et dossiers data/"
	@echo "  make secrets     Génère des secrets à coller dans .env"
	@echo "  make build       Build image Docker"
	@echo "  make up          Démarre la stack"
	@echo "  make down        Stoppe la stack"
	@echo "  make restart     Redémarre la stack"
	@echo "  make logs        Suit les logs"
	@echo "  make ps          Etat compose"
	@echo "  make shell       Shell dans le conteneur"
	@echo "  make smoke       Lance les tests API"
	@echo "  make backup      Backup SQLite local"
	@echo "  make restore BACKUP=./data/backups/file.db"

init:
	@test -f .env || cp .env.example .env
	@mkdir -p data/exports data/backups
	@chmod 750 data data/exports data/backups
	@echo "✅ Init OK. Edite .env avant make up."

secrets:
	@echo "ADMIN_TOKEN=$$(openssl rand -hex 32)"
	@echo "SESSION_SECRET=$$(openssl rand -hex 32)"
	@echo "DEFAULT_ADMIN_PASSWORD=$$(openssl rand -base64 24 | tr -d '\n')"

build:
	$(COMPOSE) build --pull

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

shell:
	$(COMPOSE) exec npm-security-dashboard sh

smoke:
	BASE_URL=$(BASE_URL) ADMIN_TOKEN=$(ADMIN_TOKEN) ./scripts/smoke-test.sh

backup:
	./scripts/backup-db.sh

restore:
	@test -n "$(BACKUP)" || (echo "Usage: make restore BACKUP=./data/backups/logs-YYYYmmdd-HHMMSS.db" && exit 1)
	./scripts/restore-db.sh "$(BACKUP)"

clean:
	$(COMPOSE) down --remove-orphans
