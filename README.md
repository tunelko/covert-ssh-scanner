# Covert SSH Scanner

> Author: **tunelko**

Herramienta de analisis de red que detecta automaticamente que canales encubiertos SSH estan disponibles en un entorno de red concreto y recomienda la tecnica optima de evasion.

---

## Tabla de contenidos

1. [Que problema resuelve](#que-problema-resuelve)
2. [Como funciona](#como-funciona)
3. [Requisitos previos](#requisitos-previos)
4. [Instalacion](#instalacion)
5. [Guia de uso](#guia-de-uso)
   - [Primer escaneo (modo simulacion)](#1-primer-escaneo-modo-simulacion)
   - [Escaneo real contra un objetivo](#2-escaneo-real-contra-un-objetivo)
   - [Generar configuraciones](#3-generar-configuraciones)
   - [Modulo esteganografico](#4-modulo-esteganografico)
6. [Referencia de comandos](#referencia-de-comandos)
7. [Arquitectura del proyecto](#arquitectura-del-proyecto)
8. [Como funciona el motor de decision](#como-funciona-el-motor-de-decision)
9. [Modulo esteganografico en detalle](#modulo-esteganografico-en-detalle)
10. [Tests](#tests)
11. [Preguntas frecuentes](#preguntas-frecuentes)
    - [Como decide que tecnica recomendar?](#como-decide-la-herramienta-que-tecnica-recomendar)
    - [Por que un puerto abierto no basta?](#por-que-un-puerto-abierto-no-basta-para-tunelizar-ssh)
    - [Como funciona el modulo esteganografico?](#como-funciona-el-modulo-esteganografico)
12. [Licencia](#licencia)

---

## Que problema resuelve

Cuando un operador necesita establecer una conexion SSH a traves de una red hostil (firewalls corporativos, redes censoras, hoteles, aeropuertos...), se enfrenta a estas preguntas:

- Esta el puerto 22 abierto? Probablemente no.
- Puedo tunelizar SSH por el puerto 443? Depende de si hay DPI.
- Hay proxy HTTP? Interceptan TLS? Filtran DNS?
- Que tecnica de evasion debo usar? Stunnel? WebSocket? obfs4? DNS tunnel?

**Covert SSH Scanner** automatiza todo ese analisis: escanea la red, detecta las restricciones activas y recomienda la mejor tecnica con configuraciones listas para usar.

---

## Como funciona

La herramienta opera en tres fases secuenciales:

```
 FASE 1: RECONOCIMIENTO          FASE 2: DECISION           FASE 3: CONFIGURACION
 ========================        =================          =====================

 TCP Probe (puertos)    ──┐                                  stunnel.conf
 HTTP Probe (proxy/TLS) ──┤     Motor de           ──►      wstunnel + nginx
 DNS Probe (filtrado)   ──┼──►  puntuacion          ──►      torrc
 ICMP Probe (ping)      ──┤     ponderado           ──►      ssh_config
 DPI Probe (inspeccion) ──┘     (6 criterios)       ──►      docker-compose.yml

         Red real                 8 tecnicas                 Ficheros listos
                                  rankeadas                  para usar
```

### Fase 1 — Reconocimiento: "que deja pasar esta red?"

Cinco sondas independientes analizan la red. Cada una hace una pregunta concreta:

| Sonda | Que detecta | Necesita root |
|---|---|---|
| `tcp_probe` | Puertos abiertos/filtrados/cerrados + banners de servicio | No |
| `http_probe` | Proxies HTTP (CONNECT y transparente) + interceptacion TLS | No |
| `dns_probe` | Manipulacion DNS, NXDOMAIN hijacking, viabilidad de tunel DNS | No |
| `icmp_probe` | ICMP permitido, restriccion de tamanio, ancho de banda estimado | Si |
| `dpi_probe` | DPI activo (SSH banner en puerto 443, SSH dentro de TLS, protocol enforcement) | No* |

*\*La sonda DPI usa sockets TCP normales, no raw sockets.*

**TCPProbe** — abre un socket TCP a cada puerto y clasifica la respuesta:

```
 Puerto 22  ──► socket.connect() ──► timeout?          → "filtered"  (firewall lo descarta)
                                 ──► RST?              → "closed"    (el host lo rechaza)
                                 ──► conecta?          → "open"      + intenta leer banner
                                                         "SSH-2.0-..." → servicio SSH
                                                         "HTTP/1.1..."  → servicio HTTP
```

**HTTPProbe** — detecta intermediarios en la ruta de red:

```
 Test 1: CONNECT proxy                    Test 2: TLS interception
 ─────────────────────                    ────────────────────────
 Envia "CONNECT dominio:443"              Conecta TLS al :443
 al puerto 80 del target                  Lee el certificado
                                          Compara issuer contra:
 Respuesta 200? → proxy forward           ├── Let's Encrypt, DigiCert  → legitimo
 Respuesta 407? → proxy con auth          └── Fortinet, Zscaler        → interceptado
 Sin respuesta? → no hay proxy
```

**DNSProbe** — compara resoluciones para detectar manipulacion:

```
                     ┌──── Sistema resolver ────► "1.2.3.4"
 "resuelve dominio" ─┤                                        iguales? → OK
                     └──── Google 8.8.8.8  ────► "1.2.3.4"   difieren? → DNS manipulado

 Tambien resuelve un dominio inexistente:
   respuesta con IP? → NXDOMAIN hijacking (el ISP redirige dominios falsos)
   error NXDOMAIN?   → DNS limpio
```

**DPIProbe** — el test mas revelador. Conecta al puerto 443 (abierto) y envia un banner SSH:

```
 sock.connect((target, 443))
 sock.sendall("SSH-2.0-OpenSSH_8.9\r\n")
     │
     ├── conexion muere con RST  → DPI detecta SSH en puerto no-SSH
     └── respuesta normal        → no hay inspeccion de protocolo
```

Si el firewall ve `SSH-2.0` en un puerto que deberia ser HTTPS y corta la conexion, sabemos que hay DPI activo. Esto cambia completamente el ranking de tecnicas.

### Fase 2 — Decision: "que tecnica usar?"

El motor de scoring recibe los resultados de las 5 sondas y puntua 8 tecnicas. Cada una se evalua en 6 dimensiones con pesos diferentes (lo mas importante pesa mas):

```
 channel_available  (peso 3.0)  →  Existe un canal de transporte abierto?
 dpi_resistance     (peso 2.5)  →  Resiste la inspeccion profunda detectada?
 bandwidth          (peso 1.5)  →  Ancho de banda estimado
 latency            (peso 1.0)  →  Retardo de la conexion
 setup_complexity   (peso 1.0)  →  Facilidad de despliegue
 stealth            (peso 1.0)  →  Lo "normal" que parece el trafico
```

Cada dimension recibe un valor entre 0.0 y 1.0 que se multiplica por su peso. El resultado es una nota de 0 a 10. Ejemplo con DPI detectado y puerto 443 abierto:

```
              channel  dpi_resist  bw    latency  setup  stealth  SCORE
 obfs4proxy    1.0      0.95      0.85    0.8     0.5    0.95     8.9
 WebSocket     1.0      0.80      0.90    0.85    0.65   0.85     8.4
 Stunnel       1.0      0.70      0.95    0.90    0.70   0.70     8.2
 DNS Tunnel    1.0      0.70      0.15    0.30    0.40   0.60     6.3
 Direct SSH    BLOCKED  ──────────────────────────────────────     ---
```

obfs4 gana porque esta disenado para DPI (0.95 en `dpi_resistance`), mientras que Stunnel baja porque el DPI puede detectar patrones SSH dentro de TLS.

### Fase 3 — Configuracion: "dame los ficheros listos"

Para la tecnica ganadora se generan ficheros de configuracion reales (no plantillas genericas). Incluyen la IP del target, el dominio, el usuario y el ProxyCommand SSH correcto:

```
 output/
 ├── ssh_config              ← Entrada para ~/.ssh/config con ProxyCommand
 ├── wstunnel-server.sh      ← Comando para arrancar el servidor
 ├── wstunnel-client.sh      ← Comando para arrancar el cliente
 ├── nginx-wstunnel.conf     ← Config nginx como reverse proxy + decoy website
 └── docker-compose.yml      ← (con --docker) Stack completo desplegable
```

---

## Requisitos previos

- **Docker** y **Docker Compose** (v2)
- Nada mas. Todas las dependencias (Python 3.12, scapy, requests, pytest, iputils, tcpdump, dnsutils) se instalan dentro de la imagen Docker.

---

## Instalacion

```bash
# 1. Clonar o descargar el proyecto
cd covert-ssh-scanner

# 2. Construir las imagenes (una sola vez)
docker compose build

# 3. Verificar que funciona
docker compose run --rm tests
```

La imagen se basa en `python:3.12-slim` y pesa aproximadamente 250 MB.

### Servicios Docker disponibles

El fichero `docker-compose.yml` define tres servicios:

| Servicio | Proposito | Puerto expuesto |
|---|---|---|
| `scanner` | Contenedor interactivo para ejecutar cualquier comando | Ninguno (usa `network_mode: host`) |
| `stego-srv` | Servidor HTTP esteganografico (PoC persistente) | **9080** |
| `tests` | Ejecuta la suite de 36 tests y sale | Ninguno |

El servicio `scanner` usa `network_mode: host` para tener acceso directo a la red del host, necesario para que las sondas TCP/DNS/ICMP funcionen contra objetivos reales. Ademas tiene las capabilities `NET_RAW` y `NET_ADMIN` para sondas ICMP y captura de paquetes.

Las configuraciones generadas se persisten en `./output/` mediante un volumen Docker.

---

## Guia de uso

### 1. Primer escaneo (modo simulacion)

El modo `--simulate` no hace conexiones reales. Usa datos de ejemplo para mostrar como se ve un escaneo completo. Ideal para entender la herramienta antes de apuntar a un objetivo real.

```bash
docker compose run --rm scanner scan --target 203.0.113.50 --domain covert.example.com --simulate
```

**Salida esperada:**

```
━━━ Network Probes ━━━
  TCP/22    : ✗ Filtered   (timeout)
  TCP/53    : ✓ Open       (DNS) [12ms]
  TCP/80    : ✓ Open       (HTTP/1.1 200 OK) [15ms]
  TCP/443   : ✓ Open       (HTTPS) [19ms]
  ...

━━━ Advanced Detection ━━━
  HTTP Proxy    : ✓ No proxy detected
  TLS Intercept : ✓ Certificate chain valid (Let's Encrypt)
  DPI Active    : ⚠ SSH banner on :443 was RST (probable DPI)
  DNS Filtering : ✓ No DNS manipulation detected

━━━ Recommended Techniques (ranked) ━━━
  #1   obfs4proxy       [Score: 8.9/10]  DPI detected → obfuscation needed
  #2   Shadowsocks      [Score: 8.5/10]  Port 443 available, AEAD evasion
  #3   WebSocket/TLS    [Score: 8.4/10]  Port 443 open, hard to fingerprint
  #4   Stunnel+SSLH     [Score: 8.2/10]  TLS wrapping viable
  #5   DNS Tunnel       [Score: 6.3/10]  DNS open, ~80 Kbps
  #6   Tor Hidden Svc   [Score: 5.4/10]  DPI may block Tor
  ✗   Direct SSH       [Blocked]        Port 22 filtered
  ✗   ICMP Tunnel      [N/A]            Requires root
```

Tambien existe `--dry-run` que muestra que sondas se ejecutarian sin hacer nada:

```bash
docker compose run --rm scanner scan --target 203.0.113.50 --dry-run
```

### 2. Escaneo real contra un objetivo

**Escaneo basico** (sin root — TCP, HTTP, DNS, DPI):

```bash
docker compose run --rm scanner scan \
  --target 198.51.100.10 \
  --domain mi-servidor.com
```

**Escaneo completo** (con root — anade ICMP):

```bash
docker compose run --rm scanner scan \
  --target 198.51.100.10 \
  --domain mi-servidor.com \
  --full
```

El flag `--full` activa la sonda ICMP que requiere raw sockets. El contenedor Docker ya tiene la capability `NET_RAW`, no hace falta configurar nada extra.

**Opciones utiles:**

| Flag | Efecto |
|---|---|
| `--target IP` | IP o hostname del servidor SSH destino (obligatorio) |
| `--domain FQDN` | Dominio para comprobaciones TLS/DNS (por defecto = target) |
| `--full` | Incluir sondas que requieren root (ICMP) |
| `--timeout N` | Timeout de cada sonda en segundos (por defecto: 5) |
| `--simulate` | Datos simulados, sin tocar la red |
| `--dry-run` | Mostrar que haria sin ejecutar |
| `--user NOMBRE` | Usuario SSH para las configs generadas (por defecto: root) |
| `--output DIR` | Directorio de salida (por defecto: `./output/`) |
| `--no-generate` | No generar configs automaticamente |

### 3. Generar configuraciones

Si ya sabes que tecnica quieres, o quieres que la herramienta elija automaticamente:

```bash
# Autodetectar la mejor tecnica (ejecuta un escaneo rapido primero)
docker compose run --rm scanner generate \
  --target 198.51.100.10 \
  --technique auto \
  --user operador

# Tecnica especifica
docker compose run --rm scanner generate \
  --target 198.51.100.10 \
  --technique websocket \
  --domain mi-servidor.com \
  --user operador

# Anadir docker-compose.yml para el despliegue
docker compose run --rm scanner generate \
  --target 198.51.100.10 \
  --technique stunnel \
  --docker
```

**Tecnicas disponibles:** `stunnel`, `sslh`, `websocket` (`ws`, `wstunnel`), `obfs4`, `dns`, `icmp`, `tor`, `shadowsocks` (`ss`), `direct`, `auto`.

**Ficheros generados** (ejemplo para `websocket`):

```
output/
├── ssh_config              # Entrada para ~/.ssh/config con ProxyCommand
├── wstunnel-server.sh      # Comando para arrancar el servidor wstunnel
├── wstunnel-client.sh      # Comando para arrancar el cliente wstunnel
├── nginx-wstunnel.conf     # Config nginx como reverse proxy con decoy website
└── docker-compose.yml      # (si se uso --docker) Stack completo desplegable
```

### 4. Modulo esteganografico

El modulo `stego` es un proof-of-concept que oculta trafico SSH dentro de peticiones HTTP que parecen navegacion web legitima. Tiene cuatro modos:

#### Demo — ver encode/decode en accion

```bash
docker compose run --rm scanner stego --mode demo
```

Muestra como 21 bytes de banner SSH (`SSH-2.0-OpenSSH_8.9\r\n`) se codifican en cookies, query parameters y JSON bodies, y se decodifican correctamente.

#### HTTP Cover — ver como se ve el trafico de cobertura

```bash
docker compose run --rm scanner stego --mode http-cover
```

Genera 3 peticiones HTTP de ejemplo mostrando como se ven los datos ocultos: User-Agent rotado, cookies que parecen tracking, JSON que parece telemetria.

#### Servidor — recibir datos ocultos

```bash
# Arrancar como servicio (background)
docker compose up stego-srv -d

# O manualmente con puerto custom
docker compose run --rm -p 9080:9080 scanner stego --mode server --port 9080
```

El servidor escucha peticiones HTTP normales. Si detecta datos esteganograficos (magic bytes + XOR mask), los decodifica y reenvia al SSH local. Si la peticion es normal, devuelve una pagina JSON "decoy" que parece una API real.

#### Cliente — enviar datos ocultos

```bash
docker compose run --rm scanner stego \
  --mode client \
  --target 198.51.100.10 \
  --port 9080 \
  --key mi-clave-secreta
```

Abre un proxy local en `127.0.0.1:2222`. Al conectar SSH a ese puerto, el trafico se codifica en peticiones HTTP y se envia al servidor stego remoto. El flag `--key` define la clave compartida para la mascara XOR (debe ser igual en cliente y servidor).

---

## Referencia de comandos

### Formato general

```bash
docker compose run --rm scanner <comando> [opciones]
```

### Comandos disponibles

| Comando | Descripcion |
|---|---|
| `scan` | Escanea la red y recomienda tecnicas |
| `generate` | Genera ficheros de configuracion para una tecnica |
| `stego` | Modulo de esteganografia HTTP (experimental) |

### scan — opciones completas

```
scan --target IP [--domain FQDN] [--full] [--timeout N]
     [--simulate] [--dry-run] [--user USER] [--output DIR]
     [--no-generate] [--skip-config]
```

### generate — opciones completas

```
generate --target IP --technique TECNICA [--domain FQDN]
         [--user USER] [--output DIR] [--docker] [--simulate]
```

### stego — opciones completas

```
stego --mode {demo,server,client,http-cover}
      [--target IP] [--port N] [--ssh-port N]
      [--local-port N] [--key CLAVE]
```

---

## Arquitectura del proyecto

```
covert-ssh-scanner/
├── Dockerfile                    # Imagen Docker (python:3.12-slim + deps)
├── docker-compose.yml            # 3 servicios: scanner, stego-srv, tests
│
├── scanner/                      # Paquete principal
│   ├── __init__.py               # Version y metadatos
│   ├── __main__.py               # Permite 'python -m scanner'
│   ├── cli.py                    # Interfaz CLI (argparse + output coloreado)
│   │
│   ├── probes/                   # FASE 1: Sondas de reconocimiento
│   │   ├── tcp_probe.py          #   Escaneo de puertos TCP + banner grabbing
│   │   ├── http_probe.py         #   Deteccion proxy HTTP + interceptacion TLS
│   │   ├── dns_probe.py          #   Analisis DNS (manipulacion, NXDOMAIN hijack)
│   │   ├── icmp_probe.py         #   ICMP echo con payloads variables (root)
│   │   └── dpi_probe.py          #   DPI: SSH banner en :443, SSH-in-TLS, proto enforcement
│   │
│   ├── engine/                   # FASE 2: Motor de decision
│   │   ├── scorer.py             #   Puntuacion ponderada de 8 tecnicas x 6 criterios
│   │   └── recommender.py        #   Orquestador: ejecuta sondas → scorer → ranking
│   │
│   ├── generators/               # FASE 3: Generacion de configuracion
│   │   ├── stunnel.py            #   Config Stunnel (server/client/SSLH/docker-compose)
│   │   ├── wstunnel.py           #   Config wstunnel + nginx reverse proxy
│   │   ├── sslh.py               #   Config SSLH multiplexer
│   │   ├── tor.py                #   Config Tor Hidden Service
│   │   └── ssh_config.py         #   Entradas ~/.ssh/config para las 8 tecnicas
│   │
│   └── stego/                    # BONUS: Esteganografia HTTP
│       └── http_stego.py         #   Encoder/Decoder + servidor/cliente HTTP stego
│
└── tests/
    └── test_probes.py            # 36 tests unitarios (simulacion + scoring + stego)
```

### Flujo de datos interno

```
cli.py → Recommender.assess()
              │
              ├── TCPProbe.run()    → TCPProbeResult
              ├── HTTPProbe.run()   → HTTPProbeResult
              ├── DNSProbe.run()    → DNSProbeResult
              ├── ICMPProbe.run()   → ICMPProbeResult  (solo con --full)
              └── DPIProbe.run()    → DPIProbeResult
                      │
                      ▼
              TechniqueScorer.score_all(probes)
                      │
                      ▼
              List[TechniqueScore]  (8 tecnicas rankeadas)
                      │
                      ▼
              *Generator.generate() (ficheros de configuracion)
```

---

## Como funciona el motor de decision

### Criterios de puntuacion

Cada tecnica se evalua en 6 dimensiones con pesos configurables:

| Criterio | Peso | Que mide |
|---|---|---|
| `channel_available` | 3.0 | Hay un canal de transporte abierto? (puerto TCP, DNS, ICMP...) |
| `dpi_resistance` | 2.5 | Resistencia a la inspeccion profunda de paquetes detectada |
| `bandwidth` | 1.5 | Ancho de banda estimado del canal |
| `latency` | 1.0 | Latencia de la conexion |
| `setup_complexity` | 1.0 | Facilidad de despliegue (invertido: mas simple = mas puntos) |
| `stealth` | 1.0 | Como de "normal" parece el trafico a un observador |

### Tecnicas evaluadas

| Tecnica | Cuando brilla | Cuando falla |
|---|---|---|
| **Direct SSH** | Puerto 22 abierto, sin DPI | Casi siempre bloqueado |
| **Stunnel+SSLH** | Puerto 443 abierto, sin interceptacion TLS | DPI detecta SSH dentro de TLS |
| **WebSocket/TLS** | Puerto 443 abierto, trafico WebSocket no inspeccionado | Proxy que no soporta WebSocket |
| **obfs4proxy** | DPI activo, necesidad de ofuscacion fuerte | Complejidad de setup alta |
| **DNS Tunnel** | Solo DNS disponible, todo lo demas bloqueado | Ancho de banda ~50-150 Kbps |
| **ICMP Tunnel** | Solo ping disponible | Muy lento, requiere root ambos lados |
| **Tor Hidden Svc** | Anonimato necesario, conectividad saliente | Latencia >500ms, Tor puede estar bloqueado |
| **Shadowsocks** | DPI activo, necesidad de buen ancho de banda | Setup moderado |

### Ejemplo de logica de scoring

Escenario: puerto 22 filtrado, puerto 443 abierto, DPI detecta SSH en :443, DNS limpio.

```
 Lo que ve el scorer:
   tcp.ports[22].state  = "filtered"   → Direct SSH bloqueado
   tcp.ports[443].state = "open"       → Stunnel/WS/obfs4/SS posibles
   dpi.ssh_banner_blocked = True       → penalizar tecnicas sin ofuscacion
   dns.tunnel_viable = True            → DNS tunnel disponible pero lento
   icmp = None                         → no testeado (sin --full)
```

Consecuencias en el ranking:

1. **obfs4proxy** (8.9) — DPI detectado, pero obfs4 genera bytes indistinguibles de ruido aleatorio. Puntua 0.95 en `dpi_resistance`.
2. **Stunnel+SSLH** (8.2) — Puerto 443 abierto, pero DPI podria detectar patrones SSH dentro de TLS. Baja a 0.70 en `dpi_resistance`.
3. **DNS Tunnel** (6.3) — DNS funciona y no le afecta el DPI, pero solo da ~80 Kbps. Puntua 0.15 en `bandwidth`.
4. **Direct SSH** (Blocked) — Puerto 22 filtrado, ni se evalua.

---

## Modulo esteganografico en detalle

### Concepto

El modulo `stego` oculta datos SSH dentro de peticiones HTTP que parecen trafico web legitimo. La cadena de codificacion:

```
 Datos SSH reales:  b"SSH-2.0-OpenSSH_8.9\r\n"  (21 bytes)
        │
        ▼  XOR con SHA-256(clave compartida)
 bytes ofuscados (no se lee "SSH" en ningun sitio)
        │
        ▼  prepend magic bytes + numero de secuencia
 \xDE\xAD  +  \x00\x03  +  <datos_masked>
        │
        ▼  base64 encode
 "3q0AA8ZpJxf5Or9QS-LM8Iad0IJ8DR_7SQ"
        │
        ▼  repartir en canales HTTP
 ┌───────────────────────────────────────────────────────────────┐
 │  GET /api/v2/analytics/collect?utm_source=3q0AA8...           │
 │  Cookie: _ga=3q0AA8Z; _gid=pJxf5Or; session_id=QS-LM8...    │
 │  User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2...)      │
 └───────────────────────────────────────────────────────────────┘
        │
        ▼  Para un observador de red, esto parece:
        "un iPhone visitando una API de analytics"
```

El servidor hace el proceso inverso: busca los magic bytes `\xDE\xAD` en cookies/query/body, deshace el base64, deshace el XOR, y obtiene los bytes SSH originales. Si la peticion no contiene magic bytes, devuelve una pagina JSON "decoy" que parece una API real.

Los datos se reparten en tres canales segun el tamanio:

| Canal | Donde se ocultan los datos | Aspecto para un observador |
|---|---|---|
| **Cookies** | Valores de cookies (`_ga`, `_gid`, `session_id`...) | Tracking/analytics cookies normales |
| **Query params** | Parametros UTM (`utm_source`, `utm_campaign`, `cd1`) | Google Analytics / marketing tags |
| **JSON body** | Campo `data` dentro de un JSON de "telemetria" | API call de analytics/eventos |

### Tecnicas anti-analisis

- **Rotacion de User-Agent**: 5 navegadores reales (Chrome, Safari, Firefox, Linux, iPhone)
- **Paths aleatorios**: `/api/v2/analytics/collect`, `/cdn/assets/config.json`...
- **Jitter temporal**: 50-200ms de delay aleatorio entre peticiones
- **Mascara XOR**: Los datos se enmascaran con SHA-256 de la clave compartida
- **Magic bytes**: `\xDE\xAD` + sequence number para identificar paquetes stego vs trafico real

### Limitaciones (es un PoC)

- XOR no es cifrado real (solo ofuscacion)
- No hay control de flujo ni reordenamiento de paquetes
- El overhead es ~1.9x (512 bytes de datos → ~962 bytes HTTP)
- No resiste analisis estadistico avanzado del trafico

---

## Tests

```bash
docker compose run --rm tests
```

### Que cubren los 36 tests

| Grupo | Tests | Que valida |
|---|---|---|
| `TestTCPProbe` | 3 | Simulacion TCP devuelve puertos correctos |
| `TestHTTPProbe` | 2 | Simulacion HTTP/TLS correcta |
| `TestDNSProbe` | 2 | Simulacion DNS + viabilidad tunel |
| `TestICMPProbe` | 2 | Simulacion ICMP + latencia |
| `TestDPIProbe` | 2 | Simulacion DPI + resultados de tests |
| `TestScorer` | 6 | Scoring correcto, ordenacion, SSH bloqueado, obfs4 alto con DPI |
| `TestRecommender` | 3 | Pipeline completo, dry-run, tecnica viable |
| `TestGenerators` | 7 | Todas las configs se generan correctamente |
| `TestSteganography` | 9 | Round-trip JSON, cookies, payloads grandes, clave incorrecta falla |

Todos los tests usan el modo `simulate` y no requieren acceso a red.

---

## Preguntas frecuentes

### Como decide la herramienta que tecnica recomendar?

Cada sonda recopila hechos sobre la red (puerto abierto/cerrado, DPI activo, DNS manipulado...). Con esos hechos, el motor de scoring evalua 8 tecnicas en 6 dimensiones ponderadas:

```
 channel_available  (peso 3.0)  →  Existe un canal de transporte abierto?
 dpi_resistance     (peso 2.5)  →  Resiste la inspeccion profunda detectada?
 bandwidth          (peso 1.5)  →  Ancho de banda estimado
 latency            (peso 1.0)  →  Retardo de la conexion
 setup_complexity   (peso 1.0)  →  Facilidad de despliegue
 stealth            (peso 1.0)  →  Lo "normal" que parece el trafico
```

Cada dimension recibe un valor entre 0.0 y 1.0 que se multiplica por su peso. El resultado es una nota de 0 a 10. La tecnica con mayor nota es la recomendada.

### Por que un puerto abierto no basta para tunelizar SSH?

Porque muchos firewalls tienen **Deep Packet Inspection (DPI)**: dejan pasar conexiones al puerto 443 pero inspeccionan los primeros bytes. Si ven `SSH-2.0-...` en lugar de un TLS ClientHello, matan la conexion con un RST.

La sonda DPI detecta exactamente esto: conecta al puerto 443 y envia un banner SSH. Si la conexion muere, el scoring penaliza a tecnicas como Stunnel (que mete SSH dentro de TLS pero con patrones detectables) y favorece a obfs4 (que genera bytes indistinguibles de ruido aleatorio).

### Como funciona el modulo esteganografico?

Transforma bytes SSH en peticiones HTTP que parecen trafico de navegacion web:

```
 bytes SSH  →  XOR con SHA-256(clave)  →  base64  →  repartir en:
                                                      ├── cookies (_ga, _gid, session_id)
                                                      ├── query params (utm_source, utm_campaign)
                                                      └── JSON body (API de "telemetria")
```

Para un observador de red, el trafico parece un navegador visitando una API de analytics. El servidor busca los magic bytes `\xDE\xAD` en las peticiones para distinguir stego de trafico real, y deshace el proceso para obtener los bytes SSH originales.

### El modulo stego es seguro para uso real?

No. Es un proof-of-concept academico. La mascara XOR no es cifrado, no hay autenticacion, y el patron de trafico no resistiria un analisis estadistico serio. Para uso real, usa las tecnicas recomendadas por el scanner (obfs4, wstunnel, etc.).

### Necesito root en el host?

No. Docker gestiona los permisos. El contenedor ya tiene las capabilities `NET_RAW` y `NET_ADMIN` configuradas en el `docker-compose.yml`, asi que el flag `--full` (sondas ICMP) funciona directamente.

### Que pasa si el puerto 9080 esta ocupado?

Edita `docker-compose.yml` y cambia `"9080:9080"` por otro puerto libre, por ejemplo `"9090:9090"`. Acuerdate de cambiar tambien el flag `--port` en el comando del servicio `stego-srv`.

### Puedo anadir mis propias tecnicas de evasion?

Si. Anade un nuevo `TechniqueID` en `scanner/engine/scorer.py`, crea el metodo `_score_mi_tecnica()` en `TechniqueScorer`, y opcionalmente un generador en `scanner/generators/`.

---

## Licencia

MIT — Ver fichero [LICENSE](LICENSE).
