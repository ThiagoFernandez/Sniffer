from scapy.all import *

import auxiliar

stats = {"IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}

# primer requisito - capturar paquetes con sniff() usando callback


def protocol_counter(packet):
    if IP in packet:
        src = packet[IP].src  # ip origen
        dst = packet[IP].dst  # ip destino

        if TCP in packet:
            flags = packet[TCP].flags  # flags
            sport = packet[TCP].sport  # puerto origen
            dport = packet[TCP].dport  # puerto destino
            print(f"[TCP] {src}:{sport} → {dst}:{dport} | flags={flags}")
            stats["TCP"] += 1

        elif UDP in packet:
            sport = packet[UDP].sport  # puerto origen
            dport = packet[UDP].dport  # puerto destino
            print(f"[UDP] {src}:{sport} → {dst}:{dport}")
            stats["UDP"] += 1

        elif ICMP in packet:
            types = {  # tipos de ICMP
                0: "echo-reply",
                3: "dest-unreachable",
                8: "echo-request",
                11: "time-exceeded",
            }
            tipo = types.get(packet[ICMP].type, packet[ICMP].type)
            print(f"[ICMP] {src} → {dst} | tipo={tipo}")
            stats["ICMP"] += 1

        else:
            stats["IP"] += 1  # Solo IP :(

    elif ARP in packet:
        types = {1: "request(who-has)", 2: "reply(is-at)"}
        hwsrc = packet[ARP].hwsrc  # mac origen
        hwdst = packet[ARP].hwdst  # mac destino
        op = types.get(packet[ARP].op, packet[ARP].op)
        print(f"[ARP] {hwsrc} --> {hwdst} | {op}")
        stats["ARP"] += 1  # ARP
    else:
        stats["OTHER"] += 1  # ARP, etc


def main():
    auxiliar.greeting_text("Welcome to the Sniffer!!!")
    try:
        sniff(
            prn=protocol_counter, store=False
        )  # este false evita que me explote la compu o sea, evita que me guarde los paquetes en memoria
    except KeyboardInterrupt:
        pass

    total = sum(stats.values())
    print(f"\nTotal packets: {total} --- stats={stats}")


main()
