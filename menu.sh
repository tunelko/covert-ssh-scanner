#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Covert SSH Scanner — Interactive Menu Wizard
# Uses charmbracelet/gum if available, falls back to plain ANSI.
# ESC returns to previous menu. English default, Spanish available.
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail
trap 'printf "\n"; exit 0' INT TERM

# ─── Constants ────────────────────────────────────────────────────────
readonly COMPOSE="docker compose"
readonly SERVICE="scanner"
readonly VERSION="1.0.0"
readonly __ESC__="__ESC__"

# ─── ANSI colors ─────────────────────────────────────────────────────
readonly RST=$'\033[0m'
readonly BOLD=$'\033[1m'
readonly DIM=$'\033[2m'
readonly RED=$'\033[91m'
readonly GREEN=$'\033[92m'
readonly YELLOW=$'\033[93m'
readonly CYAN=$'\033[96m'

# ─── Detect gum ──────────────────────────────────────────────────────
HAS_GUM=false
command -v gum &>/dev/null && HAS_GUM=true

# ═════════════════════════════════════════════════════════════════════
#  i18n — LANGUAGE SUPPORT
# ═════════════════════════════════════════════════════════════════════

LANG_ID="en"

declare -A L

load_lang() {
    case "$1" in
    es)
        LANG_ID="es"
        L[main_menu]="Menu Principal"
        L[scan_desc]="Escanear red objetivo"
        L[generate_desc]="Generar configs de tunel"
        L[stego_desc]="Esteganografia HTTP"
        L[test_desc]="Ejecutar suite de tests"
        L[build_desc]="Construir imagenes Docker"
        L[clean_desc]="Parar y limpiar todo"
        L[language_desc]="Cambiar a English"
        L[exit_desc]="Salir"
        L[select_prompt]="Selecciona [1-NUM]: "
        L[invalid]="Opcion invalida."
        L[esc_hint]="ESC = volver"
        L[gum_tip]="Tip: make install-gum para menus mejorados"
        L[target_prompt]="Target IP o hostname (obligatorio)"
        L[target_required]="Target es obligatorio."
        L[domain_prompt]="Dominio (Enter para usar target)"
        L[domain_opt_prompt]="Dominio (opcional, Enter para omitir)"
        L[user_prompt]="Usuario SSH"
        L[timeout_prompt]="Timeout por sonda (segundos)"
        L[scan_mode_prompt]="Modo de escaneo"
        L[scan_normal]="Normal — Escaneo basico (TCP/HTTP/DNS/DPI)"
        L[scan_full]="Full — Incluye ICMP (requiere root)"
        L[scan_simulate]="Simulate — Datos simulados (demo)"
        L[scan_dryrun]="Dry-run — Muestra que haria sin ejecutar"
        L[command_label]="Comando:"
        L[confirm_exec]="Ejecutar?"
        L[completed]="Completado."
        L[exit_code]="Finalizado con codigo"
        L[cancelled]="Cancelado."
        L[press_enter]="Pulsa Enter para continuar..."
        L[hdr_scan]="Network Scan"
        L[hdr_generate]="Generar Configuracion"
        L[hdr_stego]="HTTP Steganography"
        L[hdr_test]="Tests"
        L[hdr_build]="Build"
        L[hdr_clean]="Clean"
        L[technique_prompt]="Tecnica"
        L[tech_auto]="auto — Detectar automaticamente"
        L[tech_stunnel]="stunnel — Stunnel + SSLH"
        L[tech_websocket]="websocket — WebSocket sobre TLS"
        L[tech_obfs4]="obfs4 — Ofuscacion obfs4proxy"
        L[tech_dns]="dns — Tunel DNS"
        L[tech_icmp]="icmp — Tunel ICMP"
        L[tech_tor]="tor — Tor Hidden Service"
        L[tech_shadowsocks]="shadowsocks — Shadowsocks proxy"
        L[tech_sslh]="sslh — SSLH multiplexor"
        L[tech_direct]="direct — SSH directo"
        L[gen_docker_confirm]="Generar tambien docker-compose.yml?"
        L[auto_data_prompt]="Datos para auto-deteccion"
        L[auto_real]="Real — Escaneo rapido de red"
        L[auto_simulate]="Simulate — Usar datos simulados"
        L[stego_mode_prompt]="Modo"
        L[stego_demo]="demo — Ver encode/decode en accion"
        L[stego_cover]="http-cover — Ver trafico de cobertura"
        L[stego_server]="server — Arrancar servidor stego"
        L[stego_client]="client — Conectar cliente stego"
        L[listen_port]="Puerto de escucha"
        L[ssh_port_prompt]="Puerto SSH local"
        L[shared_key]="Clave compartida"
        L[stego_target]="Target del servidor stego (obligatorio)"
        L[remote_port]="Puerto del servidor stego"
        L[local_port]="Puerto local proxy"
        L[clean_warn]="Esto parara todos los contenedores, eliminara volumenes y limpiara output/."
        L[clean_confirm]="Continuar?"
        L[cleaned]="Limpio."
        L[goodbye]="Hasta luego."
        # ─── Hints ───
        L[hint_target]="IP o hostname del servidor SSH destino. Debe ser alcanzable desde tu red."
        L[hint_domain]="FQDN del servidor (ej. mi-servidor.com). Se usa para comprobar certificados TLS y DNS. Si no tienes dominio, deja el target."
        L[hint_user]="Cuenta de usuario en el servidor remoto. Se usara en las configs SSH generadas."
        L[hint_timeout]="Cuanto esperar por cada sonda antes de marcar timeout. Subir en redes lentas o distantes."
        L[hint_scan_mode]="Normal: sondas TCP/HTTP/DNS/DPI sin root. Full: anade ICMP (root). Simulate: datos de ejemplo sin tocar la red. Dry-run: muestra que haria."
        L[hint_technique]="auto ejecuta un escaneo rapido y elige la mejor. Si ya sabes que tecnica usar, seleccionala directamente."
        L[hint_domain_gen]="Si el servidor usa un dominio con certificado valido, indicalo aqui. Afecta a las configs de nginx/TLS."
        L[hint_gen_docker]="Genera un docker-compose.yml listo para desplegar el servidor del tunel. Util para setup rapido."
        L[hint_auto_data]="Real: escanea la red del target para decidir. Simulate: usa datos de ejemplo (para probar sin red)."
        L[hint_stego_mode]="demo: ver como se codifican/decodifican datos. http-cover: ver peticiones HTTP de cobertura. server: recibir datos ocultos. client: enviar datos ocultos."
        L[hint_listen_port]="Puerto donde escuchara el servidor HTTP stego. Usa uno no ocupado (default 9080 evita conflictos)."
        L[hint_ssh_port]="Puerto del demonio SSH local al que el servidor stego reenviara los datos decodificados."
        L[hint_shared_key]="Clave para la mascara XOR. DEBE ser identica en cliente y servidor. Sin ella no se pueden decodificar los datos."
        L[hint_stego_target]="IP o hostname donde esta corriendo el servidor stego (modo server)."
        L[hint_remote_port]="Puerto del servidor stego remoto al que conectara el cliente."
        L[hint_local_port]="Puerto local que aceptara conexiones SSH. Conecta con: ssh -p <puerto> user@127.0.0.1"
        ;;
    *)
        LANG_ID="en"
        L[main_menu]="Main Menu"
        L[scan_desc]="Scan target network"
        L[generate_desc]="Generate tunnel configs"
        L[stego_desc]="HTTP Steganography"
        L[test_desc]="Run test suite"
        L[build_desc]="Build Docker images"
        L[clean_desc]="Stop all and clean"
        L[language_desc]="Switch to Spanish"
        L[exit_desc]="Exit"
        L[select_prompt]="Select [1-NUM]: "
        L[invalid]="Invalid choice."
        L[esc_hint]="ESC = back"
        L[gum_tip]="Tip: make install-gum for enhanced menus"
        L[target_prompt]="Target IP or hostname (required)"
        L[target_required]="Target is required."
        L[domain_prompt]="Domain (Enter to use target)"
        L[domain_opt_prompt]="Domain (optional, Enter to skip)"
        L[user_prompt]="SSH username"
        L[timeout_prompt]="Probe timeout (seconds)"
        L[scan_mode_prompt]="Scan mode"
        L[scan_normal]="Normal — Basic scan (TCP/HTTP/DNS/DPI)"
        L[scan_full]="Full — Includes ICMP (requires root)"
        L[scan_simulate]="Simulate — Simulated data (demo)"
        L[scan_dryrun]="Dry-run — Show what it would do"
        L[command_label]="Command:"
        L[confirm_exec]="Execute?"
        L[completed]="Completed."
        L[exit_code]="Exited with code"
        L[cancelled]="Cancelled."
        L[press_enter]="Press Enter to continue..."
        L[hdr_scan]="Network Scan"
        L[hdr_generate]="Generate Configuration"
        L[hdr_stego]="HTTP Steganography"
        L[hdr_test]="Tests"
        L[hdr_build]="Build"
        L[hdr_clean]="Clean"
        L[technique_prompt]="Technique"
        L[tech_auto]="auto — Auto-detect best"
        L[tech_stunnel]="stunnel — Stunnel + SSLH"
        L[tech_websocket]="websocket — WebSocket over TLS"
        L[tech_obfs4]="obfs4 — obfs4proxy obfuscation"
        L[tech_dns]="dns — DNS Tunnel"
        L[tech_icmp]="icmp — ICMP Tunnel"
        L[tech_tor]="tor — Tor Hidden Service"
        L[tech_shadowsocks]="shadowsocks — Shadowsocks proxy"
        L[tech_sslh]="sslh — SSLH multiplexer"
        L[tech_direct]="direct — Direct SSH"
        L[gen_docker_confirm]="Also generate docker-compose.yml?"
        L[auto_data_prompt]="Data source for auto-detect"
        L[auto_real]="Real — Quick network scan"
        L[auto_simulate]="Simulate — Use simulated data"
        L[stego_mode_prompt]="Mode"
        L[stego_demo]="demo — See encode/decode in action"
        L[stego_cover]="http-cover — See cover traffic"
        L[stego_server]="server — Start stego server"
        L[stego_client]="client — Connect stego client"
        L[listen_port]="Listen port"
        L[ssh_port_prompt]="Local SSH port"
        L[shared_key]="Shared key"
        L[stego_target]="Stego server target (required)"
        L[remote_port]="Stego server port"
        L[local_port]="Local proxy port"
        L[clean_warn]="This will stop all containers, remove volumes and clean output/."
        L[clean_confirm]="Continue?"
        L[cleaned]="Cleaned."
        L[goodbye]="Goodbye."
        # ─── Hints ───
        L[hint_target]="IP or hostname of the destination SSH server. Must be reachable from your network."
        L[hint_domain]="Server FQDN (e.g. my-server.com). Used for TLS certificate and DNS checks. If no domain, leave the target value."
        L[hint_user]="User account on the remote server. Will be used in generated SSH configs."
        L[hint_timeout]="How long to wait per probe before marking as timeout. Increase on slow or distant networks."
        L[hint_scan_mode]="Normal: TCP/HTTP/DNS/DPI probes, no root. Full: adds ICMP (root). Simulate: example data, no network. Dry-run: shows plan only."
        L[hint_technique]="auto runs a quick scan and picks the best. If you already know your technique, select it directly."
        L[hint_domain_gen]="If the server uses a domain with a valid certificate, enter it here. Affects nginx/TLS configs."
        L[hint_gen_docker]="Generates a docker-compose.yml ready to deploy the tunnel server. Useful for quick setup."
        L[hint_auto_data]="Real: scans the target network to decide. Simulate: uses example data (for testing without network)."
        L[hint_stego_mode]="demo: see data encode/decode. http-cover: see HTTP cover requests. server: receive hidden data. client: send hidden data."
        L[hint_listen_port]="Port for the stego HTTP server to listen on. Use an unused port (default 9080 avoids conflicts)."
        L[hint_ssh_port]="Local SSH daemon port where the stego server forwards decoded data."
        L[hint_shared_key]="Key for XOR masking. MUST be identical on client and server. Without it, data cannot be decoded."
        L[hint_stego_target]="IP or hostname where the stego server (server mode) is running."
        L[hint_remote_port]="Port of the remote stego server the client will connect to."
        L[hint_local_port]="Local port accepting SSH connections. Connect with: ssh -p <port> user@127.0.0.1"
        ;;
    esac
}

# Initialize with English
load_lang en

# ═════════════════════════════════════════════════════════════════════
#  UI ABSTRACTION LAYER
# ═════════════════════════════════════════════════════════════════════

ui_banner() {
    if $HAS_GUM; then
        gum style \
            --border double \
            --align center \
            --width 58 \
            --padding "1 2" \
            --border-foreground 6 \
            "COVERT SSH SCANNER" \
            "Intelligent Covert Channel Detection" \
            "v${VERSION}"
    else
        printf '%s' "$CYAN" >/dev/tty
        printf '  ╔══════════════════════════════════════════════════════╗\n' >/dev/tty
        printf '  ║       COVERT SSH SCANNER — Interactive Menu         ║\n' >/dev/tty
        printf '  ║     Intelligent Covert Channel Detection v%s     ║\n' "$VERSION" >/dev/tty
        printf '  ╚══════════════════════════════════════════════════════╝\n' >/dev/tty
        printf '%s\n' "$RST" >/dev/tty
    fi
}

# _read_key — reads a single keypress, detects ESC
# Returns "ESC" if Escape pressed, otherwise the character(s)
_read_key() {
    local key
    IFS= read -rsn1 key </dev/tty
    if [[ "$key" == $'\x1b' ]]; then
        # Read any remaining escape sequence bytes
        local seq
        read -rsn2 -t 0.05 seq </dev/tty 2>/dev/null || true
        if [[ -z "$seq" ]]; then
            printf 'ESC'
            return
        fi
    fi
    printf '%s' "$key"
}

# ui_choose PROMPT OPT1 OPT2 ... → prints selection to stdout
# Returns __ESC__ if user pressed ESC
ui_choose() {
    local prompt="$1"; shift
    local opts=("$@")

    if $HAS_GUM; then
        local result
        result=$(gum choose --header "  $prompt  ${DIM}(${L[esc_hint]})${RST}" -- "${opts[@]}" 2>/dev/tty) || {
            printf '%s' "$__ESC__"
            return 0
        }
        printf '%s' "$result"
        return 0
    fi

    printf '\n  %s%s%s%s  %s(%s)%s\n\n' "$CYAN" "$BOLD" "$prompt" "$RST" "$DIM" "${L[esc_hint]}" "$RST" >/dev/tty
    local i=1
    for opt in "${opts[@]}"; do
        printf '    %s%d)%s %s\n' "$CYAN" "$i" "$RST" "$opt" >/dev/tty
        ((i++))
    done
    printf '\n' >/dev/tty

    while true; do
        local sel_prompt="${L[select_prompt]//NUM/${#opts[@]}}"
        printf '  %s' "$sel_prompt" >/dev/tty
        local line=""
        while true; do
            local ch
            ch=$(_read_key)
            if [[ "$ch" == "ESC" ]]; then
                printf '\n' >/dev/tty
                printf '%s' "$__ESC__"
                return 0
            elif [[ "$ch" == "" ]]; then
                # Enter pressed
                printf '\n' >/dev/tty
                break
            else
                printf '%s' "$ch" >/dev/tty
                line+="$ch"
            fi
        done
        if [[ "$line" =~ ^[0-9]+$ ]] && (( line >= 1 && line <= ${#opts[@]} )); then
            printf '%s' "${opts[$((line-1))]}"
            return 0
        fi
        printf '  %s%s%s\n' "$RED" "${L[invalid]}" "$RST" >/dev/tty
    done
}

# ui_input PROMPT [DEFAULT] → prints value to stdout
# Returns __ESC__ if user pressed ESC
ui_input() {
    local prompt="$1"
    local default="${2:-}"

    if $HAS_GUM; then
        local args=(--header "  $prompt  ${DIM}(${L[esc_hint]})${RST}")
        [[ -n "$default" ]] && args+=(--value "$default")
        local result
        result=$(gum input "${args[@]}" 2>/dev/tty) || {
            printf '%s' "$__ESC__"
            return 0
        }
        printf '%s' "$result"
        return 0
    fi

    local hint=""
    [[ -n "$default" ]] && hint=" [${default}]"
    printf '\n  %s%s%s%s  %s(%s)%s: ' "$BOLD" "$prompt" "$RST" "$hint" "$DIM" "${L[esc_hint]}" "$RST" >/dev/tty
    local line=""
    while true; do
        local ch
        ch=$(_read_key)
        if [[ "$ch" == "ESC" ]]; then
            printf '\n' >/dev/tty
            printf '%s' "$__ESC__"
            return 0
        elif [[ "$ch" == "" ]]; then
            # Enter
            printf '\n' >/dev/tty
            break
        elif [[ "$ch" == $'\x7f' ]] || [[ "$ch" == $'\x08' ]]; then
            # Backspace
            if [[ -n "$line" ]]; then
                line="${line%?}"
                printf '\b \b' >/dev/tty
            fi
        else
            line+="$ch"
            printf '%s' "$ch" >/dev/tty
        fi
    done
    [[ -z "$line" ]] && line="$default"
    printf '%s' "$line"
}

# ui_confirm PROMPT → exit code 0=yes 1=no
ui_confirm() {
    local prompt="$1"

    if $HAS_GUM; then
        gum confirm "  $prompt"
        return
    fi

    printf '\n  %s%s%s [y/N]: ' "$BOLD" "$prompt" "$RST" >/dev/tty
    local yn
    read -r yn </dev/tty
    [[ "$yn" =~ ^[Yy]([Ee][Ss])?$ ]]
}

ui_hint() {
    printf '  %s%s%s\n' "$DIM" "$1" "$RST" >/dev/tty
}

ui_header() {
    printf '\n  %s%s━━━ %s ━━━%s\n' "$CYAN" "$BOLD" "$1" "$RST" >/dev/tty
}

ui_info() {
    printf '  %s[*]%s %s\n' "$GREEN" "$RST" "$1" >/dev/tty
}

ui_warn() {
    printf '  %s[!]%s %s\n' "$YELLOW" "$RST" "$1" >/dev/tty
}

ui_error() {
    printf '  %s[x]%s %s\n' "$RED" "$RST" "$1" >/dev/tty
}

# ═════════════════════════════════════════════════════════════════════
#  RUN COMMAND WITH CONFIRMATION
# ═════════════════════════════════════════════════════════════════════

run_cmd() {
    local -a cmd=("$@")
    printf '\n  %s%s%s %s\n' "$BOLD" "${L[command_label]}" "$RST" "${cmd[*]}" >/dev/tty

    if ui_confirm "${L[confirm_exec]}"; then
        printf '\n' >/dev/tty
        set +e
        "${cmd[@]}"
        local rc=$?
        set -e
        printf '\n' >/dev/tty
        if [[ $rc -eq 0 ]]; then
            ui_info "${L[completed]}"
        else
            ui_warn "${L[exit_code]} $rc."
        fi
    else
        ui_info "${L[cancelled]}"
    fi

    printf '\n' >/dev/tty
    read -rsp "  ${L[press_enter]}" -n1 </dev/tty >/dev/tty
    printf '\n' >/dev/tty
}

# ═════════════════════════════════════════════════════════════════════
#  SUBMENUS
# ═════════════════════════════════════════════════════════════════════

# ─── Scan ─────────────────────────────────────────────────────────────
menu_scan() {
    ui_header "${L[hdr_scan]}"

    ui_hint "${L[hint_target]}"
    local target=""
    while [[ -z "$target" ]]; do
        target=$(ui_input "${L[target_prompt]}")
        [[ "$target" == "$__ESC__" ]] && return
        [[ -z "$target" ]] && ui_error "${L[target_required]}"
    done

    ui_hint "${L[hint_domain]}"
    local domain
    domain=$(ui_input "${L[domain_prompt]}" "$target")
    [[ "$domain" == "$__ESC__" ]] && return

    ui_hint "${L[hint_user]}"
    local user
    user=$(ui_input "${L[user_prompt]}" "root")
    [[ "$user" == "$__ESC__" ]] && return

    ui_hint "${L[hint_timeout]}"
    local timeout
    timeout=$(ui_input "${L[timeout_prompt]}" "5")
    [[ "$timeout" == "$__ESC__" ]] && return

    ui_hint "${L[hint_scan_mode]}"
    local mode
    mode=$(ui_choose "${L[scan_mode_prompt]}" \
        "${L[scan_normal]}" \
        "${L[scan_full]}" \
        "${L[scan_simulate]}" \
        "${L[scan_dryrun]}")
    [[ "$mode" == "$__ESC__" ]] && return

    local -a cmd=($COMPOSE run --rm $SERVICE scan
        --target "$target"
        --domain "$domain"
        --user "$user"
        --timeout "$timeout")

    local action="${mode%% —*}"
    case "$action" in
        Full)     cmd+=(--full) ;;
        Simulate) cmd+=(--simulate) ;;
        Dry-run)  cmd+=(--dry-run) ;;
    esac

    run_cmd "${cmd[@]}"
}

# ─── Generate ─────────────────────────────────────────────────────────
menu_generate() {
    ui_header "${L[hdr_generate]}"

    ui_hint "${L[hint_target]}"
    local target=""
    while [[ -z "$target" ]]; do
        target=$(ui_input "${L[target_prompt]}")
        [[ "$target" == "$__ESC__" ]] && return
        [[ -z "$target" ]] && ui_error "${L[target_required]}"
    done

    ui_hint "${L[hint_technique]}"
    local technique
    technique=$(ui_choose "${L[technique_prompt]}" \
        "${L[tech_auto]}" \
        "${L[tech_stunnel]}" \
        "${L[tech_websocket]}" \
        "${L[tech_obfs4]}" \
        "${L[tech_dns]}" \
        "${L[tech_icmp]}" \
        "${L[tech_tor]}" \
        "${L[tech_shadowsocks]}" \
        "${L[tech_sslh]}" \
        "${L[tech_direct]}")
    [[ "$technique" == "$__ESC__" ]] && return
    technique="${technique%% —*}"

    ui_hint "${L[hint_domain_gen]}"
    local domain
    domain=$(ui_input "${L[domain_opt_prompt]}" "")
    [[ "$domain" == "$__ESC__" ]] && return

    ui_hint "${L[hint_user]}"
    local user
    user=$(ui_input "${L[user_prompt]}" "root")
    [[ "$user" == "$__ESC__" ]] && return

    local -a cmd=($COMPOSE run --rm $SERVICE generate
        --target "$target"
        --technique "$technique"
        --user "$user")

    [[ -n "$domain" ]] && cmd+=(--domain "$domain")

    ui_hint "${L[hint_gen_docker]}"
    if ui_confirm "${L[gen_docker_confirm]}"; then
        cmd+=(--docker)
    fi

    if [[ "$technique" == "auto" ]]; then
        ui_hint "${L[hint_auto_data]}"
        local sim
        sim=$(ui_choose "${L[auto_data_prompt]}" \
            "${L[auto_real]}" \
            "${L[auto_simulate]}")
        [[ "$sim" == "$__ESC__" ]] && return
        [[ "${sim%% —*}" == "Simulate" ]] && cmd+=(--simulate)
    fi

    run_cmd "${cmd[@]}"
}

# ─── Stego ────────────────────────────────────────────────────────────
menu_stego() {
    ui_header "${L[hdr_stego]}"

    ui_hint "${L[hint_stego_mode]}"
    local mode
    mode=$(ui_choose "${L[stego_mode_prompt]}" \
        "${L[stego_demo]}" \
        "${L[stego_cover]}" \
        "${L[stego_server]}" \
        "${L[stego_client]}")
    [[ "$mode" == "$__ESC__" ]] && return
    mode="${mode%% —*}"

    local -a cmd=($COMPOSE run --rm $SERVICE stego --mode "$mode")

    case "$mode" in
        server)
            ui_hint "${L[hint_listen_port]}"
            local port
            port=$(ui_input "${L[listen_port]}" "9080")
            [[ "$port" == "$__ESC__" ]] && return
            ui_hint "${L[hint_ssh_port]}"
            local ssh_port
            ssh_port=$(ui_input "${L[ssh_port_prompt]}" "22")
            [[ "$ssh_port" == "$__ESC__" ]] && return
            ui_hint "${L[hint_shared_key]}"
            local key
            key=$(ui_input "${L[shared_key]}" "default")
            [[ "$key" == "$__ESC__" ]] && return
            cmd+=(--port "$port" --ssh-port "$ssh_port" --key "$key")
            ;;
        client)
            ui_hint "${L[hint_stego_target]}"
            local target=""
            while [[ -z "$target" ]]; do
                target=$(ui_input "${L[stego_target]}")
                [[ "$target" == "$__ESC__" ]] && return
                [[ -z "$target" ]] && ui_error "${L[target_required]}"
            done
            ui_hint "${L[hint_remote_port]}"
            local port
            port=$(ui_input "${L[remote_port]}" "9080")
            [[ "$port" == "$__ESC__" ]] && return
            ui_hint "${L[hint_local_port]}"
            local local_port
            local_port=$(ui_input "${L[local_port]}" "2222")
            [[ "$local_port" == "$__ESC__" ]] && return
            ui_hint "${L[hint_shared_key]}"
            local key
            key=$(ui_input "${L[shared_key]}" "default")
            [[ "$key" == "$__ESC__" ]] && return
            cmd+=(--target "$target" --port "$port"
                  --local-port "$local_port" --key "$key")
            ;;
    esac

    run_cmd "${cmd[@]}"
}

# ─── Tests ────────────────────────────────────────────────────────────
menu_test() {
    ui_header "${L[hdr_test]}"
    run_cmd $COMPOSE run --rm tests
}

# ─── Build ────────────────────────────────────────────────────────────
menu_build() {
    ui_header "${L[hdr_build]}"
    run_cmd $COMPOSE build
}

# ─── Clean ────────────────────────────────────────────────────────────
menu_clean() {
    ui_header "${L[hdr_clean]}"
    ui_warn "${L[clean_warn]}"
    if ui_confirm "${L[clean_confirm]}"; then
        set +e
        $COMPOSE down -v 2>/dev/null
        rm -f output/*.conf output/*.cfg output/*.sh output/*.yml \
            output/ssh_config output/torrc-*
        set -e
        ui_info "${L[cleaned]}"
    else
        ui_info "${L[cancelled]}"
    fi
    printf '\n' >/dev/tty
    read -rsp "  ${L[press_enter]}" -n1 </dev/tty >/dev/tty
    printf '\n' >/dev/tty
}

# ═════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═════════════════════════════════════════════════════════════════════

main() {
    while true; do
        clear >/dev/tty 2>/dev/null || true
        ui_banner

        if ! $HAS_GUM; then
            printf '  %s%s%s\n' "$DIM" "${L[gum_tip]}" "$RST" >/dev/tty
        fi

        local choice
        choice=$(ui_choose "${L[main_menu]}" \
            "Scan — ${L[scan_desc]}" \
            "Generate — ${L[generate_desc]}" \
            "Stego — ${L[stego_desc]}" \
            "Test — ${L[test_desc]}" \
            "Build — ${L[build_desc]}" \
            "Clean — ${L[clean_desc]}" \
            "Language — ${L[language_desc]}" \
            "Exit — ${L[exit_desc]}")

        local action="${choice%% —*}"

        case "$action" in
            Scan)     menu_scan     ;;
            Generate) menu_generate ;;
            Stego)    menu_stego    ;;
            Test)     menu_test     ;;
            Build)    menu_build    ;;
            Clean)    menu_clean    ;;
            Language)
                if [[ "$LANG_ID" == "en" ]]; then
                    load_lang es
                else
                    load_lang en
                fi
                ;;
            Exit|"$__ESC__")
                printf '\n'; ui_info "${L[goodbye]}"; exit 0 ;;
        esac
    done
}

main "$@"
