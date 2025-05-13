import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
from shutil import which

from core.logger_plugin import setup_plugin_logger

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
NIKTO_LEVELS_PATH = os.path.join(ROOT_DIR, "config", "plugins", "nikto.json")

container_log = logging.getLogger()
plugin_log = setup_plugin_logger("nikto")


def is_installed() -> bool:
    return which("nikto") is not None and os.path.exists("/opt/nikto/program")


def fix_invalid_json_escapes(s):
    try:
        s = re.sub(r"\\(?![\"\\/bfnrtu])", r"\\\\", s)
        s = s.replace("\r", "\\r").replace("\n", "\\n")
        return s
    except Exception as e:
        raise RuntimeError(
            f"Ошибка при очистке JSON от некорректных escape-символов: {e}"
        )


def run_nikto(target: str, suffix: str, args: str):
    temp_file = tempfile.NamedTemporaryFile(
        delete=False, suffix=f"_{suffix}_nikto.json"
    )
    output_path = temp_file.name
    temp_file.close()

    container_log.info(f"Создан временный файл для Nikto: {output_path}")

    cmd = (
        ["nikto", "-h", target]
        + args.strip().split()
        + ["-Format", "json", "-o", output_path]
    )
    container_log.info(f"Запуск Nikto на {target}: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    log_parts = [f"Запуск Nikto на {target}: {' '.join(cmd)}"]
    if result.stdout.strip():
        log_parts.append(result.stdout.strip())
    if result.stderr.strip():
        log_parts.append(f"[STDERR]:\n{result.stderr.strip()}")
    plugin_log.info("\n".join(log_parts))

    if result.returncode != 0:
        raise RuntimeError(f"Nikto завершился с ошибкой: {result.stderr.strip()}")

    if not os.path.exists(output_path):
        raise RuntimeError("Nikto не создал JSON-файл")

    with open(output_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        raise RuntimeError("Nikto JSON-файл пустой (0 байт)")

    try:
        content = fix_invalid_json_escapes(content)
        data = json.loads(content)
        if not data:
            container_log.warning(
                "Nikto завершился без уязвимостей — JSON пустой список."
            )
    except json.JSONDecodeError:
        raise RuntimeError("Nikto вернул некорректный JSON")

    return output_path


def parse(json_path: str, source_label: str = "unknown"):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            raw = f.read()
            raw = fix_invalid_json_escapes(raw)
            data = json.loads(raw)

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


def should_merge_entries():
    return False


def build_args(flags: str, ports: list[int], tuning: str) -> str:
    port_str = f"-p {','.join(map(str, ports))}" if ports else ""
    tuning_str = f"-Tuning {tuning}" if tuning else ""
    return f"{tuning_str} {flags} {port_str}".strip()


async def scan(config):
    ip = config.get("scan_config", {}).get("target_ip")
    domain = config.get("scan_config", {}).get("target_domain")
    plugin_config = next(
        (p for p in config.get("plugins", []) if p["name"] == "nikto"), {}
    )
    level = plugin_config.get("level", "easy")

    with open(NIKTO_LEVELS_PATH) as f:
        level_config = json.load(f)["levels"].get(level, {})

    tasks = []
    sources = []

    def enqueue_tasks(target, target_type):
        for proto in ["http", "https"]:
            conf = level_config.get(target_type, {}).get(proto, {})
            if conf.get("flags"):
                args = build_args(
                    conf.get("flags", ""), conf.get("ports", []), conf.get("tuning", "")
                )
                suffix = f"{target_type}_{proto}"
                tasks.append(asyncio.to_thread(run_nikto, target, suffix, args))
                sources.append(suffix)

    if ip:
        enqueue_tasks(ip, "ip")
    if domain:
        enqueue_tasks(domain, "domain")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid = []
    for path, src in zip(results, sources):
        if isinstance(path, Exception):
            container_log.error(f"Nikto ошибка в {src}: {path}")
        else:
            valid.append({"plugin": "nikto", "path": path, "source": src})

    return valid


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
    result = asyncio.run(scan(CONFIG))
    print(json.dumps(result, indent=2, ensure_ascii=False))
