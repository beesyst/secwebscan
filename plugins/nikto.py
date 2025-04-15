import json
import subprocess
from datetime import datetime

CONFIG_PATH = "/config/config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

TARGET = CONFIG["scan_config"].get("target_domain")
if not TARGET:
    raise ValueError("Для nikto требуется target_domain, но он не указан в конфиге.")


def scan_with_nikto():
    output_path = "/results/nikto.json"
    cmd = f"nikto -h https://{TARGET} -p 443 -o {output_path} -Format json -Display V -ssl -followredirects"

    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        raise RuntimeError(f"Nikto завершился с ошибкой: {stderr.decode().strip()}")

    return output_path


def parse(json_path):
    results = []

    try:
        with open(json_path, "r") as f:
            raw = f.read()
            data = json.loads(raw)

        if not data or "vulnerabilities" not in data[0]:
            return results

        parsed_entries = []
        for vuln in data[0]["vulnerabilities"]:
            parsed_entries.append(
                {
                    "url": vuln.get("url", "-"),
                    "method": vuln.get("method", "-"),
                    "msg": vuln.get("msg", "-"),
                    "id": vuln.get("id", "-"),
                    "severity": "info",
                }
            )

        if parsed_entries:
            results.append(
                {
                    "target": TARGET,
                    "module": "nikto",
                    "type": "nikto",
                    "severity": "info",
                    "data": parsed_entries,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге Nikto: {e}")

    return results


def get_summary(data):
    return " | ".join(
        f"{d.get('url', '-')}: {d.get('msg', '-')[:40]}"
        for d in data
        if isinstance(d, dict)
    )


def get_column_order():
    return ["url", "method", "msg", "id"]


if __name__ == "__main__":
    json_file = scan_with_nikto()
    parsed = parse(json_file)
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
