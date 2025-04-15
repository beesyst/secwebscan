import ipaddress
import json
import os
import subprocess
from datetime import datetime

CONFIG_PATH = "/config/config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

# Пытаемся взять сначала домен, иначе IP
TARGET = CONFIG["scan_config"].get("target_domain") or CONFIG["scan_config"].get(
    "target_ip"
)

if not TARGET:
    raise ValueError(
        "Для dig требуется target_domain или target_ip, но они не указаны."
    )


def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def scan_with_dig():
    args = ""
    level = "easy"
    for plugin in CONFIG["plugins"]:
        if plugin["name"] == "dig":
            level = plugin.get("level", "easy")
            args = plugin.get("levels", {}).get(level, {}).get("args", "")
            break

    output_path = "/results/dig.json"
    entries = []
    base_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def run_and_parse(cmd, section):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split("\n")

            current_section = section
            for line in lines:
                if line.startswith(";; ANSWER SECTION:"):
                    current_section = "answer"
                    continue
                elif line.startswith(";; AUTHORITY SECTION:"):
                    current_section = "authority"
                    continue
                elif line.startswith(";; ADDITIONAL SECTION:"):
                    current_section = "additional"
                    continue
                elif line.startswith(";") or not line.strip():
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    name = parts[0]
                    ttl = parts[1]
                    rtype = parts[3]
                    data = " ".join(parts[4:])
                    entries.append(
                        {
                            "target": TARGET,
                            "module": "dig",
                            "severity": "info",
                            "section": current_section,
                            "name": name,
                            "ttl": int(ttl),
                            "type": rtype,
                            "data": data,
                            "created_at": base_time,
                        }
                    )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Ошибка выполнения dig: {e.stderr.strip()}")

    # Основной запрос
    cmd = ["dig"]
    if is_ip(TARGET):
        cmd += ["-x", TARGET]
    else:
        cmd += args.split() + [TARGET]
    run_and_parse(cmd, "answer")

    # Дополнительные секции на уровне middle и выше
    if level in ["middle", "hard", "extreme"] and not is_ip(TARGET):
        additional_queries = [
            ["dig", "+dnssec", TARGET],
            ["dig", "+trace", TARGET],
            ["dig", "TXT", TARGET],
            ["dig", f"_dmarc.{TARGET}", "TXT"],
            ["dig", f"default._domainkey.{TARGET}", "TXT"],
        ]
        for query in additional_queries:
            run_and_parse(query, "extra")

    with open(output_path, "w") as f:
        json.dump(entries, f, indent=2)

    return output_path


def parse(json_path):
    results = []

    try:
        if not os.path.exists(json_path):
            return []

        with open(json_path, "r") as f:
            data = json.load(f)

        if not isinstance(data, list) or not data:
            return []

        results.append(
            {
                "target": TARGET,
                "module": "dig",
                "severity": "info",
                "data": data,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге dig.json: {e}")

    return results


def get_summary(data):
    return " | ".join(
        f"{d.get('type', '-')} → {d.get('data', '-')}"
        for d in data
        if isinstance(d, dict)
    )


if __name__ == "__main__":
    json_file = scan_with_dig()
    parsed = parse(json_file)
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
