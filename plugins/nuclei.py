import json
import os
import subprocess
from datetime import datetime

CONFIG_PATH = "/config/config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

TARGET = CONFIG["scan_config"].get("target_domain")
if not TARGET:
    raise ValueError("Для nuclei требуется target_domain, но он не указан в конфиге.")


def scan_with_nuclei():
    output_path = "/results/nuclei.json"
    cmd = f"nuclei -u http://{TARGET} -jsonl -t /root/nuclei-templates -o {output_path}"

    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        raise RuntimeError(f"nuclei завершился с ошибкой: {stderr.decode().strip()}")

    return output_path


def parse(json_path):
    results = []

    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Файл {json_path} не найден")

    if os.path.getsize(json_path) == 0:
        return []

    try:
        with open(json_path, "r") as f:
            entries = [json.loads(line) for line in f if line.strip()]

        parsed_entries = []
        for entry in entries:
            parsed_entries.append(
                {
                    "templateID": entry.get("templateID", "-"),
                    "info.name": entry.get("info", {}).get("name", "-"),
                    "info.severity": entry.get("info", {}).get("severity", "-"),
                    "matched-at": entry.get("matched-at", "-"),
                    "type": entry.get("type", "-"),
                    "host": entry.get("host", "-"),
                }
            )

        if parsed_entries:
            results.append(
                {
                    "target": TARGET,
                    "module": "nuclei",
                    "severity": "high",
                    "data": parsed_entries,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге nuclei: {e}")

    return results


def get_summary(data):
    return " | ".join(
        f"{d.get('templateID', '?')} - {d.get('info.name', '?')}"
        for d in data
        if isinstance(d, dict)
    )


def get_column_order():
    return [
        "templateID",
        "info.name",
        "info.severity",
        "matched-at",
        "type",
        "host",
    ]


if __name__ == "__main__":
    json_file = scan_with_nuclei()
    parsed = parse(json_file)
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
