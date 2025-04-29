import json
import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")


def run_nmap(target: str, suffix: str, args: str):
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{suffix}.xml")
    output_path = temp_file.name
    temp_file.close()

    logging.info(f"Создан временный файл для Nmap: {output_path}")

    cmd = f"nmap {args} {target} -oX {output_path}"
    logging.info(f"Запуск Nmap на {target}: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Ошибка выполнения Nmap для {target}: {result.stderr.strip()}")
        raise RuntimeError(f"Nmap завершился с ошибкой: {result.stderr.strip()}")

    if result.stdout:
        logging.info(f"[Nmap вывод для {target}]:\n{result.stdout.strip()}")

    return output_path


def parse(xml_path: str, source_label: str = "unknown"):
    """Парсер для XML вывода nmap."""
    results = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        host = root.find("host")
        ports = host.find("ports") if host is not None else None

        if ports is not None:
            for port in ports.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")

                data = {
                    "port": int(port.attrib.get("portid", 0)),
                    "protocol": port.attrib.get("protocol", "-"),
                    "state": (
                        state_el.attrib.get("state", "-")
                        if state_el is not None
                        else "-"
                    ),
                    "reason": (
                        state_el.attrib.get("reason", "-")
                        if state_el is not None
                        else "-"
                    ),
                    "service_name": (
                        service_el.attrib.get("name", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "product": (
                        service_el.attrib.get("product", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "version": (
                        service_el.attrib.get("version", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "extra": (
                        service_el.attrib.get("extrainfo", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "cpe": (
                        service_el.findtext("cpe", default="-")
                        if service_el is not None
                        else "-"
                    ),
                    "script_output": "; ".join(
                        s.attrib.get("output", "") for s in port.findall("script")
                    )
                    or "-",
                    "source": source_label,
                }

                results.append(data)

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге XML файла {xml_path}: {e}")

    return results


def get_important_fields():
    return [
        "port",
        "protocol",
        "state",
        "reason",
        "service_name",
        "product",
        "version",
        "extra",
        "cpe",
        "script_output",
    ]


def merge_entries(ip_entries, domain_entries):
    merged = {}
    important_fields = get_important_fields()

    def is_empty(entry):
        """Проверка, все ли важные поля пустые."""
        return all(
            str(entry.get(k, "-")).strip() in ["-", "", "null", "None", "0"]
            for k in important_fields
        )

    ip_entries = [e for e in ip_entries if not is_empty(e)]
    domain_entries = [e for e in domain_entries if not is_empty(e)]

    for entry in ip_entries + domain_entries:
        key = (entry.get("port"), entry.get("protocol"), entry.get("service_name"))

        if key in merged:
            existing = merged[key]
            if all(entry.get(k, "-") == existing.get(k, "-") for k in important_fields):
                merged[key]["source"] = "Both"
            else:
                new_key = key + ("duplicate",)
                merged[new_key] = entry
        else:
            merged[key] = entry

    return list(merged.values())


def scan(plugin=None, config=None, debug=False):
    ip = config.get("scan_config", {}).get("target_ip")
    domain = config.get("scan_config", {}).get("target_domain")
    plugin_config = next(
        (p for p in config.get("plugins", []) if p["name"] == "nmap"), {}
    )

    level = plugin_config.get("level", "easy")
    args = plugin_config.get("levels", {}).get(level, {}).get("args", "")

    generated_paths = []

    if ip:
        path = run_nmap(ip, "ip", args)
        generated_paths.append({"plugin": "nmap", "path": path, "source": "IP"})

    if domain:
        path = run_nmap(domain, "domain", args)
        generated_paths.append({"plugin": "nmap", "path": path, "source": "Domain"})

    return generated_paths


def get_summary(data):
    """Краткое описание для использования в будущих отчётах."""
    return " | ".join(
        f"{d.get('port', '?')}/{d.get('protocol', '?')} {d.get('state', '?')}"
        for d in data
        if isinstance(d, dict)
    )


def get_column_order():
    """Порядок колонок для TERMINAL и HTML вывода."""
    return [
        "source",
        "port",
        "protocol",
        "state",
        "reason",
        "service_name",
        "product",
        "version",
        "extra",
        "cpe",
        "script_output",
    ]


def get_wide_fields():
    return [
        "product",
        "version",
        "extra",
        "script_output",
        "cpe",
    ]


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
    print(json.dumps(scan(config=CONFIG, debug=True), indent=2, ensure_ascii=False))
