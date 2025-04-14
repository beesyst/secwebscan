import json
import subprocess
from datetime import datetime
import os

CONFIG_PATH = "/config/config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

TARGET = CONFIG["scan_config"]["target"]


def scan_with_nuclei():
    output_path = "/results/nuclei.json"
    cmd = f"nuclei -u http://{TARGET} -json -o {output_path}"
    subprocess.run(cmd, shell=True)
    return output_path


def parse(json_path):
    results = []

    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Файл {json_path} не найден")

    try:
        with open(json_path, "r") as f:
            entries = [json.loads(line) for line in f if line.strip()]

        if entries:
            results.append({
                "target": TARGET,
                "module": "nuclei",
                "severity": "high",
                "data": entries,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге JSON: {e}")

    return results


def get_summary(data):
    return " | ".join(
        f"{d.get('templateID', '?')} - {d.get('info', {}).get('name', '?')}"
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
    print(json.dumps(parsed, indent=2))
