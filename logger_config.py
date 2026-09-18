import logging
import sys
import json
import colorama

colorama.init()

class ConsoleColorFormatter(logging.Formatter):
    """
    Formatter para la consola.
    Inyecta colores ANSI en la salida sin ensuciar el objeto LogRecord.
    """
    COLORS = {
        "[TCP]": colorama.Fore.GREEN,
        "[UDP]": colorama.Fore.BLUE,
        "[ICMP]": colorama.Fore.YELLOW,
        "[ARP]": colorama.Fore.CYAN,
        "[HTTP]": colorama.Fore.MAGENTA,
    }

    def format(self, record):
        msg = super().format(record)

        if record.levelno >= logging.WARNING:
            return f"{colorama.Fore.RED}{msg}{colorama.Fore.RESET}"

        for prefix, color in self.COLORS.items():
            if msg.startswith(prefix):
                msg = msg.replace(prefix, f"{color}{prefix}{colorama.Fore.RESET}", 1)
                break

        return msg

class JSONFormatter(logging.Formatter):
    """
    Formatter para archivo.
    Emite un JSON estructurado por cada evento. Combina el mensaje base
    con los campos inyectados via `extra={"alert_meta": {...}}`.
    """
    def format(self, record):
        log_obj = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "msg": record.getMessage()
        }

        # Si el evento trae metadata estructurada, la fusionamos al nivel raiz del JSON
        if hasattr(record, "alert_meta") and record.alert_meta:
            log_obj.update(record.alert_meta)

        # ensure_ascii=False evita que '→' se convierta en '\u2192'
        return json.dumps(log_obj, ensure_ascii=False)

def configure_logger(name="sniffer", silent=False):
    logger = logging.getLogger(name)

    if not logger.hasHandlers():
        # 1. Handler de Consola
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ConsoleColorFormatter("%(message)s"))
        logger.addHandler(console_handler)

        # 2. Handler de Archivo: Exclusivo para alertas
        file_handler = logging.FileHandler("sniffer_alerts.json")
        file_handler.setLevel(logging.WARNING)  # Filtro independiente: solo alertas reales
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

        logger.propagate = False

    # El nivel base del logger dicta qué eventos entran al "embudo" principal.
    # En silent, cerramos la llave general a WARNING. En normal, entra INFO pero
    # el file_handler filtra lo que sobra.
    if silent:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)

    return logger
