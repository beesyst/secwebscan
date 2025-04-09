import json
import re
import subprocess
from datetime import datetime

CONFIG_PATH = "/config/config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

TARGET = CONFIG["scan_config"]["target"]


def scan_with_nikto():
    output_path = "/results/nikto.json"
    cmd = f"nikto -h http://{TARGET} -o {output_path} -Format json"
    subprocess.run(cmd, shell=True)
    return output_path


def parse(json_path):
    results = []

    try:
        with open(json_path, "r") as f:
            raw = f.read()

        try:
            data = json.loads(raw)
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                raw_output = data[0].get("data", "")
            elif isinstance(data, dict):
                raw_output = data.get("data", "")
            else:
                raw_output = raw
        except Exception:
            raw_output = raw

        parsed_entries = []

        for line in raw_output.splitlines():
            match = re.match(r"^\+ (\/[^\s:]*):\s+(.*)", line)
            if match:
                uri = match.group(1).strip()
                message = match.group(2).strip()
                parsed_entries.append(
                    {"uri": uri, "message": message, "severity": "info"}
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
        f"{d.get('uri', '-')}: {d.get('message', '-')[:40]}"
        for d in data
        if isinstance(d, dict)
    )


if __name__ == "__main__":
    json_file = scan_with_nikto()
    parsed = parse(json_file)
    print(json.dumps(parsed, indent=2))
