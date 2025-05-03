import asyncio
import json
import logging
import os
import subprocess
import tempfile

from core.logger_plugin import setup_plugin_logger

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")

container_log = logging.getLogger()
plugin_log = setup_plugin_logger("nikto")


def run_nikto(target: str, args: str):
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix="_nikto.json")
    output_path = temp_file.name
    temp_file.close()

    container_log.info(f"Создан временный файл для Nikto: {output_path}")

    cmd = f"nikto -h {target} {args} -o {output_path} -Format json"
    container_log.info(f"Запуск Nikto на {target}: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.stdout:
        plugin_log.info(f"STDOUT Nikto на {target}:\n{result.stdout.strip()}")
    if result.stderr:
        plugin_log.warning(f"STDERR Nikto на {target}:\n{result.stderr.strip()}")

    if result.returncode != 0:
        raise RuntimeError(f"Nikto завершился с ошибкой: {result.stderr.strip()}")

    if not os.path.exists(output_path) or os.stat(output_path).st_size == 0:
        raise RuntimeError(
            "Nikto не создал JSON-файл или файл пустой. "
            "Возможно, превышено время выполнения или неправильные флаги."
        )

    return output_path


def parse(json_path: str, source_label: str = "Domain"):
    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        if not data or not isinstance(data, list):
            return []

        findings = []
        for item in data:
            for vuln in item.get("vulnerabilities", []):
                findings.append(
                    {
                        "url": vuln.get("url", "-"),
                        "method": vuln.get("method", "-"),
                        "msg": vuln.get("msg", "-"),
                        "id": vuln.get("id", "-"),
                        "references": vuln.get("references", "-"),
                        "source": source_label,
                    }
                )

        return findings

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге Nikto JSON: {e}")


def get_important_fields():
    return ["msg"]


def get_column_order():
    return ["source", "url", "method", "msg", "id", "references"]


def get_wide_fields():
    return ["url", "msg", "references"]


async def scan(plugin=None, config=None, debug=False):
    domain = config.get("scan_config", {}).get("target_domain")
    if not domain:
        raise ValueError("Для nikto требуется target_domain")

    plugin_config = next(
        (p for p in config.get("plugins", []) if p["name"] == "nikto"), {}
    )
    level = plugin_config.get("level", "easy")
    args = plugin_config.get("levels", {}).get(level, {}).get("args", "")

    path = await asyncio.to_thread(run_nikto, domain, args)
    return [{"plugin": "nikto", "path": path, "source": "Domain"}]


def should_merge_entries():
    return False


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)

    result = asyncio.run(scan(config=CONFIG, debug=True))
    print(json.dumps(result, indent=2, ensure_ascii=False))
