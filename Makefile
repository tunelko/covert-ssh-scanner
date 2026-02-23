# ─── Covert SSH Scanner — Makefile ────────────────────────────────────
# Atajos para los comandos Docker Compose del proyecto.
# Uso rapido:  make              (wizard interactivo)
#              make help         (ver todos los targets)
#              make scan TARGET=203.0.113.50 DOMAIN=example.com
# ──────────────────────────────────────────────────────────────────────

SHELL         := /bin/bash
.DEFAULT_GOAL := menu

COMPOSE       := docker compose
SERVICE       := scanner
TESTS_SVC     := tests
STEGO_SVC     := stego-srv

# ─── Variables configurables ──────────────────────────────────────────
TARGET        ?=
DOMAIN        ?=
USER          ?= root
TIMEOUT       ?= 5
TECHNIQUE     ?= auto
STEGO_TARGET  ?=
STEGO_PORT    ?= 9080
STEGO_KEY     ?= default
LOCAL_PORT    ?= 2222
SSH_PORT      ?= 22

# ─── Core ─────────────────────────────────────────────────────────────

.PHONY: menu
menu: ## Lanzar wizard interactivo
	@bash menu.sh

.PHONY: help
help: ## Mostrar esta ayuda
	@printf '\n  \033[1mCovert SSH Scanner — Targets disponibles:\033[0m\n\n'
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{printf "  \033[96m%-18s\033[0m %s\n", $$1, $$2}'
	@printf '\n'

.PHONY: build
build: ## Construir imagenes Docker
	$(COMPOSE) build

.PHONY: test
test: ## Ejecutar suite de tests (36 tests)
	$(COMPOSE) run --rm $(TESTS_SVC)

# ─── Scan ─────────────────────────────────────────────────────────────
# make scan TARGET=203.0.113.50 [DOMAIN=x] [USER=root] [FULL=1] [SIMULATE=1] [DRY_RUN=1]

.PHONY: scan
scan: _require-target ## Escanear red (TARGET=x obligatorio)
	$(COMPOSE) run --rm $(SERVICE) scan \
		--target $(TARGET) \
		$(if $(DOMAIN),--domain $(DOMAIN)) \
		--user $(USER) --timeout $(TIMEOUT) \
		$(if $(FULL),--full) \
		$(if $(SIMULATE),--simulate) \
		$(if $(DRY_RUN),--dry-run) \
		$(if $(NO_GENERATE),--no-generate)

.PHONY: scan-simulate
scan-simulate: _require-target ## Escaneo simulado (TARGET=x obligatorio)
	$(COMPOSE) run --rm $(SERVICE) scan --target $(TARGET) \
		$(if $(DOMAIN),--domain $(DOMAIN)) --simulate

# ─── Generate ─────────────────────────────────────────────────────────
# make generate TARGET=203.0.113.50 [TECHNIQUE=auto] [DOMAIN=x] [DOCKER=1]

.PHONY: generate
generate: _require-target ## Generar configs (TARGET=x, TECHNIQUE=auto)
	$(COMPOSE) run --rm $(SERVICE) generate \
		--target $(TARGET) --technique $(TECHNIQUE) \
		$(if $(DOMAIN),--domain $(DOMAIN)) \
		--user $(USER) \
		$(if $(DOCKER),--docker) \
		$(if $(SIMULATE),--simulate)

# ─── Stego ────────────────────────────────────────────────────────────

.PHONY: stego-demo
stego-demo: ## Demo de esteganografia (encode/decode)
	$(COMPOSE) run --rm $(SERVICE) stego --mode demo

.PHONY: stego-cover
stego-cover: ## Demo de trafico de cobertura HTTP
	$(COMPOSE) run --rm $(SERVICE) stego --mode http-cover

.PHONY: stego-server
stego-server: ## Arrancar servidor stego (background, puerto 9080)
	$(COMPOSE) up $(STEGO_SVC) -d
	@printf '\n  \033[92mServidor stego arrancado en puerto $(STEGO_PORT)\033[0m\n'
	@printf '  Parar con: make stego-down\n\n'

.PHONY: stego-client
stego-client: ## Cliente stego (STEGO_TARGET=x obligatorio)
ifndef STEGO_TARGET
	$(error STEGO_TARGET obligatorio. Uso: make stego-client STEGO_TARGET=198.51.100.10)
endif
	$(COMPOSE) run --rm $(SERVICE) stego --mode client \
		--target $(STEGO_TARGET) --port $(STEGO_PORT) \
		--local-port $(LOCAL_PORT) --key $(STEGO_KEY)

.PHONY: stego-down
stego-down: ## Parar servidor stego y servicios
	$(COMPOSE) down

# ─── Utilidades ───────────────────────────────────────────────────────

.PHONY: shell
shell: ## Abrir shell bash en contenedor scanner
	$(COMPOSE) run --rm --entrypoint bash $(SERVICE)

.PHONY: logs
logs: ## Ver logs de contenedores
	$(COMPOSE) logs --tail=50 -f

.PHONY: clean
clean: ## Parar todo, limpiar volumenes y output
	$(COMPOSE) down -v 2>/dev/null || true
	@rm -f output/*.conf output/*.cfg output/*.sh output/*.yml \
		output/ssh_config output/torrc-*
	@printf '  \033[92mLimpio.\033[0m\n'

.PHONY: install-gum
install-gum: ## Instalar charmbracelet/gum (mejora visual del menu)
	@command -v gum >/dev/null 2>&1 && { printf '  gum ya instalado: '; gum --version; } || { \
		printf '  Instalando gum...\n'; \
		GUM_VERSION=$$(curl -fsSL https://api.github.com/repos/charmbracelet/gum/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4 | sed 's/^v//'); \
		ARCH=$$(uname -m | sed 's/aarch64/arm64/'); \
		OS=$$(uname -s); \
		rm -rf /tmp/gum-install && mkdir -p /tmp/gum-install && \
		curl -fsSL "https://github.com/charmbracelet/gum/releases/download/v$${GUM_VERSION}/gum_$${GUM_VERSION}_$${OS}_$${ARCH}.tar.gz" \
			| tar -xz -C /tmp/gum-install --strip-components=1 && \
		mv /tmp/gum-install/gum /usr/local/bin/gum && \
		chmod +x /usr/local/bin/gum && \
		rm -rf /tmp/gum-install && \
		printf '  \033[92mgum %s instalado.\033[0m\n' "$${GUM_VERSION}"; \
	}

# ─── Helpers internos ─────────────────────────────────────────────────

.PHONY: _require-target
_require-target:
ifndef TARGET
	$(error TARGET obligatorio. Uso: make $(MAKECMDGOALS) TARGET=203.0.113.50)
endif
