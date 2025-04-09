import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

CONFIG_PATH = "/config/config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

TARGET = CONFIG["scan_config"]["target"]


def scan_with_nmap():
    output_path = "/results/nmap.xml"
    cmd = f"nmap -oX {output_path} {TARGET}"
    subprocess.run(cmd, shell=True)
    return output_path


def parse(xml_path):
    results = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        host = root.find("host")
        address = (
            host.find("address").attrib.get("addr", "-") if host is not None else "-"
        )
        hostname_el = host.find("hostnames/hostname")
        hostname = (
            hostname_el.attrib.get("name", "") if hostname_el is not None else "-"
        )
        ports = host.find("ports") if host is not None else None

        entries = []
        if ports is not None:
            for port in ports.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")

                entry = {
                    "port": int(port.attrib.get("portid", 0)),
                    "protocol": port.attrib.get("protocol", ""),
                    "state": (
                        state_el.attrib.get("state", "") if state_el is not None else ""
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
                        [s.attrib.get("output", "") for s in port.findall("script")]
                    )
                    or "-",
                }
                entries.append(entry)

        if entries:
            results.append(
                {
                    "target": address,
                    "module": "nmap",
                    "severity": "info",
                    "data": entries,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге XML: {e}")

    return results


def get_summary(data):
    return " | ".join(
        f"{d.get('port', '?')}/{d.get('protocol', '?')} {d.get('state', '?')}"
        for d in data
        if isinstance(d, dict)
    )


if __name__ == "__main__":
    xml_file = scan_with_nmap()
    parsed = parse(xml_file)
    print(json.dumps(parsed, indent=2))
