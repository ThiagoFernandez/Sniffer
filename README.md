# Sniffer

Sniffer de paquetes de línea de comandos construido en Python con **Scapy**. Captura tráfico en vivo, lo decodifica por protocolo, detecta dos patrones de ataque en tiempo real y guarda todo en un `.pcap` abrible con Wireshark.

Proyecto de la Fase 2 del roadmap de Python para ciberseguridad — enfocado en captura en vivo, análisis de encabezados y detección por ventana deslizante.

---

## Features

- **Decodificación por protocolo** — TCP, UDP, ICMP, ARP e IP suelto, cada uno con su propio formato y color
- **Traducción de flags TCP** — no muestra `PA`, muestra qué significa (`PSH-ACK --- DATA`), lo mismo con los tipos ICMP y las operaciones ARP
- **Detección de SYN flood / port scanning** — alerta cuando una IP supera los 10 SYN en una ventana de 3 segundos
- **Detección de ARP scanning** — alerta cuando una MAC supera los 20 `who-has` en 3 segundos
- **Extracción de peticiones HTTP** — reconstruye `Host` y path del tráfico en claro hacia el puerto 80
- **Volcado de payload** — muestra el contenido como texto si es legible, o los primeros 64 bytes en hexadecimal si es binario
- **Escritura incremental a `.pcap`** — cada paquete va directo a disco, no se acumula en RAM
- **Filtros BPF** — la misma sintaxis de filtro que Wireshark y tcpdump
- **Modo silencioso** — captura sin imprimir nada, solo genera el `.pcap`
- **Sugerencias ante error** — si el filtro o la interfaz son inválidos, lista ejemplos válidos y las interfaces disponibles
- **Estadísticas finales** — conteo por protocolo al cerrar

---

## Instalación

```bash
git clone https://github.com/ThiagoFernandez/Sniffer.git
cd Sniffer
pip install scapy colorama
```

En Windows hace falta [Npcap](https://npcap.com/) para capturar en vivo.

---

## Uso

```bash
# Linux/macOS: sockets crudos, requiere root
sudo python main.py [opciones]

# Windows: terminal como administrador
python main.py [opciones]
```

| Flag | Descripción |
|------|-------------|
| `-f`, `--filter` | Filtro BPF. Ej: `"tcp port 80"` |
| `-i`, `--interface` | Interfaz de red. Ej: `eth0`, `wlan0` |
| `-c`, `--count` | Cantidad de paquetes a capturar (`0` = infinito) |
| `-s`, `--silent` | Modo silencioso: no imprime, solo guarda el `.pcap` |

### Ejemplos

```bash
# Capturar todo hasta Ctrl+C
sudo python main.py

# Solo tráfico HTTP en la interfaz wlan0
sudo python main.py -f "tcp port 80" -i wlan0

# 500 paquetes y salir
sudo python main.py -c 500

# Captura de fondo sin salida por consola
sudo python main.py -s -f "not arp"

# Todo lo que involucre a un host puntual
sudo python main.py -f "host 192.168.1.10"
```

---

## Output

```
------------------ Welcome to the Sniffer!!! -------------------
[TCP] 192.168.1.35:52134 → 142.250.79.14:443 | flags=SYN --- Starting conexion
[TCP] 142.250.79.14:443 → 192.168.1.35:52134 | flags=SYN-ACK --- Conexion accepted
[HTTP] 192.168.1.35 → example.com/index.html
[UDP] 192.168.1.35:53422 → 192.168.1.1:53
    └─ payload (34b, binario): 8a1c0100000100000000000003777777...
[ICMP] 192.168.1.35 → 8.8.8.8 | tipo=echo-request
[ARP] a4:5e:60:c1:22:9f --> ff:ff:ff:ff:ff:ff | request(who-has)
[SYN FLOOD/PORT SCANNING] from 192.168.1.99
[ARP SCAN] from a4:5e:60:c1:22:9f

Total packets: 1284 --- stats={'IP': 12, 'TCP': 902, 'UDP': 310, 'ICMP': 8, 'ARP': 44, 'OTHER': 8}
Saved to sniffer_20260804_213012.pcap
```

El `.pcap` generado se abre directamente con Wireshark o `tshark` para análisis posterior.

---

## Cómo funciona

### Detección por ventana deslizante

Ambos detectores usan la misma técnica. Por cada evento se guarda un timestamp asociado al origen y, antes de evaluar, se descartan los que quedaron fuera de la ventana:

```python
syn_tracker[src].append(now)
syn_tracker[src] = [t for t in syn_tracker[src] if now - t < SYN_WINDOW]
if len(syn_tracker[src]) > SYN_THRESHOLD:
    # alerta
```

La lista nunca crece indefinidamente: se poda en cada paquete. Los umbrales son constantes al principio del archivo y se ajustan según la red:

| Constante | Default | Qué detecta |
|-----------|---------|-------------|
| `SYN_THRESHOLD` / `SYN_WINDOW` | 10 SYN / 3 s | SYN flood o port scan |
| `ARP_THRESHOLD` / `ARP_WINDOW` | 20 requests / 3 s | Barrido ARP de la subred |

Un SYN suelto es tráfico normal — cualquier conexión empieza así. Lo anómalo es el volumen concentrado en el tiempo, que es exactamente lo que mide la ventana.

### Memoria constante

`sniff()` se llama con `store=False` y cada paquete se escribe al `PcapWriter` apenas llega. La captura puede correr horas sin que crezca el uso de RAM, que es el problema clásico de los sniffers hechos con Scapy.

---

## Dependencias

| Librería | Instalación | Uso |
|----------|-------------|-----|
| `scapy` | `pip install scapy` | Captura, decodificación y escritura de `.pcap` |
| `colorama` | `pip install colorama` | Colores cross-platform |
| `argparse`, `collections`, `datetime`, `time` | stdlib | CLI, trackers y timestamps |

---

## Consideraciones legales

Capturar tráfico de una red implica ver comunicaciones ajenas. Usar solo en redes propias o con autorización explícita del responsable. En muchas jurisdicciones la interceptación no autorizada es un delito.

---

## Limitaciones conocidas

- Solo IPv4 — el tráfico IPv6 cae en el contador `OTHER`
- La extracción HTTP solo funciona sobre el puerto 80 en texto plano; HTTPS es opaco por diseño
- Los detectores no tienen lista blanca: un router o un escáner legítimo pueden disparar alertas
- Los trackers no se limpian por completo: en capturas muy largas con muchos orígenes distintos, el diccionario crece
- No reensambla flujos TCP: cada paquete se analiza aislado

---

*Parte del roadmap de Python para Ciberseguridad*
