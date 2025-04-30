import asyncio
import json
import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from core.logger_plugin import setup_plugin_logger

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")

container_log = logging.getLogger()
plugin_log = setup_plugin_logger("nmap")


def run_nmap(target: str, suffix: str, args: str):
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{suffix}.xml")
    output_path = temp_file.name
    temp_file.close()

    container_log.info(f"Создан временный файл для Nmap: {output_path}")

    cmd = f"nmap {args} {target} -oX {output_path}"
    container_log.info(f"Запуск Nmap на {target}: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.stdout:
        plugin_log.info(f"Запуск Nmap на {target}: {cmd}\n{result.stdout.strip()}")

    if result.stderr:
        plugin_log.warning(f"[STDERR {target}]:\n{result.stderr.strip()}")

    if result.returncode != 0:
        raise RuntimeError(f"Nmap завершился с ошибкой: {result.stderr.strip()}")

    return output_path


def parse(xml_path: str, source_label: str = "unknown"):
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


async def scan(plugin=None, config=None, debug=False):
    ip = config.get("scan_config", {}).get("target_ip")
    domain = config.get("scan_config", {}).get("target_domain")
    plugin_config = next(
        (p for p in config.get("plugins", []) if p["name"] == "nmap"), {}
    )

    level = plugin_config.get("level", "easy")
    args = plugin_config.get("levels", {}).get(level, {}).get("args", "")

    tasks = []
    sources = []

    if ip:
        tasks.append(asyncio.to_thread(run_nmap, ip, "ip", args))
        sources.append("IP")

    if domain:
        tasks.append(asyncio.to_thread(run_nmap, domain, "domain", args))
        sources.append("Domain")

    results = await asyncio.gather(*tasks)

    return [
        {"plugin": "nmap", "path": path, "source": src}
        for path, src in zip(results, sources)
    ]


def get_summary(data):
    return " | ".join(
        f"{d.get('port', '?')}/{d.get('protocol', '?')} {d.get('state', '?')}"
        for d in data
        if isinstance(d, dict)
    )


def get_column_order():
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
    return ["product", "version", "extra", "script_output", "cpe"]


if __name__ == "__main__":
    import asyncio

    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
    result = asyncio.run(scan(config=CONFIG, debug=True))
    print(json.dumps(result, indent=2, ensure_ascii=False))
