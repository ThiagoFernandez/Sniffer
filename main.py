import argparse
import time
from collections import defaultdict
from datetime import datetime

import colorama
from scapy.all import *

import auxiliar

colorama.init()
SYN_THRESOLD = 10  # 10 porque es estandar pero podes poner lo q vos queres aca
SYN_WINDOW = 3  # ACA LO MISMO, CON 3 segundos ya basta para saber q se esta haciendo un ataque SYN flood o port scanning

stats = {"IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
captured = []
syn_tracker = defaultdict(list)
args = None


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
    # tendria q agregar un parametro tipo count asi no siempre hago control+c
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite)",
    )
    args = parser.parse_args()
    return args


def protocol_counter(packet):
    captured.append(packet)
    if IP in packet:
        src = packet[IP].src  # ip origen
        dst = packet[IP].dst  # ip destino

        if TCP in packet:
            if packet[TCP].dport == 80:  # http
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
                        print(f"[HTTP] {src} → {host}{path}")
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
                "SE": "SYN-ECE --- Handsahge with ECN enable",
            }
            flags = str(packet[TCP].flags)  # flags a string para poder mapearlo
            if flags == "S":
                now = time.time()
                syn_tracker[src].append(now)  # cargo la ip y el tiempo
                syn_tracker[src] = [
                    t for t in syn_tracker[src] if now - t < SYN_WINDOW
                ]  # la limpio la lista (sliding window algorithm)
                if (
                    len(syn_tracker[src]) > SYN_THRESOLD
                ):  # si hay mas de 10 paquetes en el window, es un ataque SYN flood o port scanning
                    if not args.silent:
                        print(
                            f"{colorama.Fore.RED}[SYN FLOOD/PORT SCANNING] {colorama.Fore.RESET}from{src}"
                        )
            description = flags_map.get(flags, flags)
            sport = packet[TCP].sport  # puerto origen
            dport = packet[TCP].dport  # puerto destino
            if not args.silent:
                print(
                    f"{colorama.Fore.GREEN}[TCP]{colorama.Fore.RESET} {src}:{sport} → {dst}:{dport} | flags={description}"
                )
            stats["TCP"] += 1

        elif UDP in packet:
            sport = packet[UDP].sport  # puerto origen
            dport = packet[UDP].dport  # puerto destino
            if not args.silent:
                print(
                    f"{colorama.Fore.BLUE}[UDP]{colorama.Fore.RESET} {src}:{sport} → {dst}:{dport}"
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
            if not args.silent:
                print(
                    f"{colorama.Fore.YELLOW}[ICMP]{colorama.Fore.RESET} {src} → {dst} | tipo={tipo}"
                )
            stats["ICMP"] += 1

        else:
            if not args.silent:
                print(f"Just IP --- {packet}")
            stats["IP"] += 1  # Solo IP :(

    elif ARP in packet:
        types = {1: "request(who-has)", 2: "reply(is-at)"}
        hwsrc = packet[ARP].hwsrc  # mac origen
        hwdst = packet[ARP].hwdst  # mac destino
        op = types.get(packet[ARP].op, packet[ARP].op)
        if not args.silent:
            print(
                f"{colorama.Fore.CYAN}[ARP]{colorama.Fore.RESET} {hwsrc} --> {hwdst} | {op}"
            )
        stats["ARP"] += 1  # ARP
    else:
        stats["OTHER"] += 1  # IPv6, etc


def main():
    global args
    auxiliar.greeting_text("Welcome to the Sniffer!!!")
    args = argument_parser()

    try:
        sniff(
            prn=protocol_counter,
            store=False,
            filter=args.filter,
            iface=args.interface,
            count=args.count,
        )  # este false evita que me explote la compu o sea, evita que me guarde los paquetes en memoria
    except Scapy_Exception as e:
        print(f"Invalid filter: {e}\nThese are some examples")
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
    except ValueError as e:
        print(f"Invalid interface: {e}\nThese are some examples")
        examples = get_if_list()
        auxiliar.show_options(examples)
        return
    except KeyboardInterrupt:
        pass
    total = sum(stats.values())
    print(f"\nTotal packets: {total} --- stats={stats}")
    path = get_path()
    wrpcap(path, captured)
    print(f"Saved to {path}")


main()
