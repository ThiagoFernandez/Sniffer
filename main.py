import argparse
import logging
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import *

import auxiliar
from logger_config import configure_logger  # Importamos la configuracion externa

# Obtenemos el logger global (se configurara mas adelante en el main)
logger = logging.getLogger("sniffer")


# --- SYN flood / port scanning: muchos SYN desde la MISMA ip ---
SYN_THRESHOLD = 10
SYN_WINDOW = 3

# --- ARP scan: muchos requests desde la MISMA mac ---
ARP_THRESHOLD = 20
ARP_WINDOW = 3

# --- ARP / CAM flood: muchas MACs DISTINTAS en la ventana ---
ARP_FLOOD_WINDOW = 5
ARP_FLOOD_THRESHOLD = 50  # MACs distintas, no paquetes

ALERT_COOLDOWN = 5  # segundos minimos entre alertas repetidas del mismo (tipo, origen)
TRACKER_CAP = 1000  # a partir de aca vale la pena pagar la limpieza O(n)

writer = None
pcap_path = None
stats = {"IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
syn_tracker = defaultdict(list)  # ip  -> [timestamps]
arp_tracker = defaultdict(list)  # mac -> [timestamps]
arp_flood_tracker = {}  # mac -> ultima vez vista
alert_cooldown = {}  # (tipo, origen) -> ultima alerta
args = None


# ---------------------------------------------------------------- deteccion


def alert(tipo, origen, mensaje, now, meta=None):
    """Imprime como mucho una alerta cada ALERT_COOLDOWN por (tipo, origen).

    Sin esto, una vez cruzado el umbral imprimis una linea por cada paquete
    que llega y te tapa la consola justo cuando mas querias leerla.
    """
    clave = (tipo, origen)
    if now - alert_cooldown.get(clave, 0.0) < ALERT_COOLDOWN:
        return
    alert_cooldown[clave] = now

    # mismo patron amortizado que el resto: chequeo O(1), limpieza O(n) solo si crecio
    if len(alert_cooldown) > TRACKER_CAP:
        for k in [k for k, t in alert_cooldown.items() if now - t >= ALERT_COOLDOWN]:
            del alert_cooldown[k]

    # Pasamos la metadata estructurada al logger mediante el kwarg extra
    logger.warning("[%s] %s", tipo, mensaje, extra={"alert_meta": meta or {}})


def prune_tracker(tracker, now, window):
    """Borra las claves cuyos timestamps ya vencieron todos.

    Sin esto, los defaultdict crecen una clave por cada ip/mac vista y nunca
    se achican: bajo un flood con origenes rotativos el ataque te llena la
    RAM del propio sniffer.
    """
    if len(tracker) <= TRACKER_CAP:
        return
    muertas = [k for k, ts in tracker.items() if not ts or now - ts[-1] >= window]
    for k in muertas:
        del tracker[k]


def arp_flood_check(mac, now):
    """Cardinalidad de MACs distintas sobre una ventana deslizante.

    El dict es mac -> ultima vez vista: una MAC que sigue hablando se refresca
    sola, y la que aparecio una vez y desaparecio se cae de la ventana.
    """
    arp_flood_tracker[mac] = now  # mutacion, NO reasignacion del nombre

    if len(arp_flood_tracker) <= ARP_FLOOD_THRESHOLD:
        return  # O(1), caso comun: ni siquiera con basura vieja llegas al umbral

    # recien aca pagas el O(n). Lista primero: no se puede borrar mientras iteras
    vencidas = [m for m, t in arp_flood_tracker.items() if now - t >= ARP_FLOOD_WINDOW]
    for m in vencidas:
        del arp_flood_tracker[m]

    if len(arp_flood_tracker) > ARP_FLOOD_THRESHOLD:
        alert(
            "ARP FLOOD",
            None,  # la mac del ultimo paquete no dice nada si el atacante las rota
            f"{len(arp_flood_tracker)} MACs distintas en {ARP_FLOOD_WINDOW}s",
            now,
            meta={
                "event": "arp_flood",
                "distinct_macs": len(arp_flood_tracker),
                "window_s": ARP_FLOOD_WINDOW
            }
        )

# ---------------------------------------------------------------- setup

def get_path():
    now = datetime.now()
    return f"sniffer_{now.strftime('%Y%m%d_%H%M%S')}.pcap"


def argument_parser():
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument("-f", "--filter", help="BPF filter. Ej: 'tcp port 80'")
    parser.add_argument("-i", "--interface", help="Network interface. Ej: 'eth0'")
    parser.add_argument(
        "-s", "--silent", action="store_true", help="Silent mode - only save .pcap"
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite)",
    )
    return parser.parse_args()

# ---------------------------------------------------------------- handler

def protocol_counter(packet):
    if writer:
        writer.write(packet)  # este cambio hace q vaya al disco y no me piole la ram

    if IP in packet:
        src = packet[IP].src  # ip origen
        dst = packet[IP].dst  # ip destino

        if TCP in packet:
            # Optimizacion: Evita procesar payload HTTP si estamos en modo silencioso y q no detone una papa con cables
            if packet[TCP].dport == 80 and logger.isEnabledFor(logging.INFO):  # http
                payload = bytes(packet[TCP].payload)
                try:
                    txt = payload.decode("utf-8", errors="ignore")
                    lines = txt.split("\r\n")

                    primera = lines[0].split(" ")  # path es la primera linea
                    path = primera[1] if len(primera) > 1 else ""

                    # host esta en los headers
                    host = ""
                    for line in lines:
                        if line.startswith("Host:"):
                            host = line.split(":", 1)[1].strip()
                            break

                    if host and path:
                        logger.info("[HTTP] %s → %s%s", src, host, path)
                except Exception:
                    pass

            flags_map = {
                "S": "SYN --- Starting conexion",
                "A": "ACK --- Reception confirmed",
                "F": "FIN --- Closing conexion",
                "R": "RST --- Force closing conexion ",
                "P": "PSH --- Process this right now - real data",
                "U": "URG --- Top priority data (rare)",
                "SA": "SYN-ACK --- Conexion accepted",
                "PA": "PSH-ACK --- DATA",
                "RA": "RST-ACK --- Reset",
                "FA": "FIN-ACK --- Closing",
                "E": "ECE --- Congestion notification",
                "C": "CWR --- Congestion's answer",
                "SE": "SYN-ECE --- Handshake with ECN enable",
            }
            flags = str(packet[TCP].flags)  # flags a string para poder mapearlo

            if flags == "S":
                now = time.time()
                syn_tracker[src].append(now)  # cargo la ip y el tiempo
                syn_tracker[src] = [
                    t for t in syn_tracker[src] if now - t < SYN_WINDOW
                ]  # limpio la lista (sliding window)
                if len(syn_tracker[src]) > SYN_THRESHOLD:
                    alert(
                        "SYN FLOOD/PORT SCAN",
                        src,
                        f"from {src} ({len(syn_tracker[src])} SYN en {SYN_WINDOW}s)",
                        now,
                        meta={
                            "event": "syn_flood",
                            "src_ip": src,
                            "syn_count": len(syn_tracker[src]),
                            "window_s": SYN_WINDOW
                        }
                    )
                prune_tracker(syn_tracker, now, SYN_WINDOW)

            description = flags_map.get(flags, flags)
            sport = packet[TCP].sport  # puerto origen
            dport = packet[TCP].dport  # puerto destino
            logger.info(
                "[TCP] %s:%s → %s:%s | flags=%s",
                src, sport, dst, dport, description
            )
            stats["TCP"] += 1

        elif UDP in packet:
            sport = packet[UDP].sport  # puerto origen
            dport = packet[UDP].dport  # puerto destino
            logger.info(
                "[UDP] %s:%s → %s:%s",
                src, sport, dst, dport
            )
            stats["UDP"] += 1

        elif ICMP in packet:
            types = {  # tipos de ICMP
                0: "echo-reply",
                3: "dest-unreachable",
                8: "echo-request",
                11: "time-exceeded",
            }
            tipo = types.get(packet[ICMP].type, packet[ICMP].type)
            logger.info(
                "[ICMP] %s → %s | tipo=%s",
                src, dst, tipo
            )
            stats["ICMP"] += 1

        else:
            logger.info("Just IP --- %s", packet.summary())
            stats["IP"] += 1  # Solo IP :(

    elif ARP in packet:
        types = {1: "request(who-has)", 2: "reply(is-at)"}
        hwsrc = packet[ARP].hwsrc  # mac origen (payload ARP)
        hwdst = packet[ARP].hwdst  # mac destino (payload ARP)
        op = types.get(packet[ARP].op, packet[ARP].op)
        now = time.time()

        # La CAM del switch se llena con el MAC del frame Ethernet, no con el
        # del payload ARP. Normalmente coinciden; un atacante puede separarlos.
        ether_src = packet[Ether].src if Ether in packet else hwsrc

        # el flood se cuenta sobre TODOS los ARP (requests, replies, gratuitos)
        arp_flood_check(ether_src, now)

        if ether_src != hwsrc:
            alert(
                "ARP MISMATCH",
                hwsrc,
                f"Ether.src={ether_src} != ARP.hwsrc={hwsrc}",
                now,
                meta={
                    "event": "arp_mismatch",
                    "hwsrc": hwsrc,
                    "ethersrc": ether_src
                }
            )

        # el scan si es especifico de los requests: quien barre la subnet pregunta
        if op == "request(who-has)":
            arp_tracker[hwsrc].append(now)
            arp_tracker[hwsrc] = [t for t in arp_tracker[hwsrc] if now - t < ARP_WINDOW]
            if len(arp_tracker[hwsrc]) > ARP_THRESHOLD:
                alert(
                    "ARP SCAN",
                    hwsrc,
                    f"from {hwsrc} ({len(arp_tracker[hwsrc])} requests en {ARP_WINDOW}s)",
                    now,
                    meta={
                        "event": "arp_scan",
                        "src_mac": hwsrc,
                        "request_count": len(arp_tracker[hwsrc]),
                        "window_s": ARP_WINDOW
                    }
                )
            prune_tracker(arp_tracker, now, ARP_WINDOW)

        logger.info(
            "[ARP] %s --> %s | %s",
            hwsrc, hwdst, op
        )
        stats["ARP"] += 1

    else:
        stats["OTHER"] += 1  # IPv6, etc

    show_payload(packet)


def show_payload(packet, indent="    "):
    # Optimizacion: Si estamos en modo silencioso, evitamos decodificar payloads
    if not logger.isEnabledFor(logging.INFO):
        return

    if Raw not in packet:
        return  # protocolo puro, sin datos de aplicación (ej: SYN, ARP)

    data = bytes(packet[Raw].load)
    try:
        txt = data.decode("utf-8")
        logger.info("%s└─ payload (%sb): %r", indent, len(data), txt)
    except UnicodeDecodeError:
        logger.info("%s└─ payload (%sb, binario): %s", indent, len(data), data[:64].hex())


# ---------------------------------------------------------------- main


def main():
    global args, writer, pcap_path

    auxiliar.greeting_text("Welcome to the Sniffer!!!")
    args = argument_parser()

    # Delegamos la configuracion a la funcion importada
    configure_logger(name="sniffer", silent=args.silent)

    pcap_path = get_path()  # se guarda una sola vez y se reusa al final
    writer = PcapWriter(pcap_path, append=True, sync=True)

    try:
        sniff(
            prn=protocol_counter,
            store=False,  # evita que me guarde los paquetes en memoria
            filter=args.filter,
            iface=args.interface,
            count=args.count,
        )
    except Scapy_Exception as e:
        logger.error("Invalid filter: %s\nThese are some examples", e)
        examples = [
            "tcp",
            "udp",
            "icmp",
            "arp",
            "tcp or udp",
            "tcp and port 443",
            "udp and port 53",
            "not arp",
            "host 192.168.0.1",
            "src host 192.168.0.1",
            "dst host 192.168.0.1",
            "tcp and host 192.168.0.1",
            "port 443",
            "src port 53",
            "dst port 80",
        ]
        auxiliar.show_options(examples)
        return
    except (ValueError, OSError) as e:
        logger.error("Invalid interface: %s\nThese are some examples", e)
        auxiliar.show_options(get_if_list())
        return
    except KeyboardInterrupt:
        pass
    finally:
        if writer:
            writer.close()

    total = sum(stats.values())
    print(f"\nTotal packets: {total} --- stats={stats}")
    print(f"Saved to {pcap_path}")


if __name__ == "__main__":
    main()
