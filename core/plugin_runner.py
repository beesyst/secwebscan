import asyncio
import importlib.util
import json
import logging
import os
import shutil
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")

from logger_container import setup_container_logger

with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

setup_container_logger()

PLUGINS = CONFIG.get("plugins", [])
SCAN_CONFIG = CONFIG.get("scan_config", {})
TARGET_IP = SCAN_CONFIG.get("target_ip")
TARGET_DOMAIN = SCAN_CONFIG.get("target_domain")

if not TARGET_IP and not TARGET_DOMAIN:
    raise ValueError(
        "Не указан ни target_ip, ни target_domain в конфиге. Укажите хотя бы один."
    )


def is_tool_installed(tool_name):
    return shutil.which(tool_name) is not None


async def install_plugin(plugin):
    name = plugin["name"]
    if not plugin.get("install"):
        return True

    if is_tool_installed(name):
        logging.info(f"{name} уже установлен. Пропускаем установку.")
        return True

    logging.info(f"Установка зависимостей для {name}...")
    is_root = os.geteuid() == 0

    for cmd in plugin["install"]:
        if not is_root:
            cmd = f"sudo {cmd}"

        logging.info(f"➡ Выполняется: {cmd}")
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if stdout:
            logging.debug(f"{name} STDOUT:\n{stdout.decode().strip()}")
        if process.returncode != 0:
            logging.error(
                f"Установка {name} не удалась на команде: {cmd}\n{stderr.decode().strip()}"
            )
            return False

    logging.info(f"{name} успешно установлен.")
    return True


async def run_tool(plugin):
    name = plugin["name"]
    output_path = os.path.join(ROOT_DIR, plugin["output"])
    parser_type = plugin.get("parser", "json")

    if not plugin.get("enabled", False):
        logging.info(f"{name} отключен в конфиге. Пропускаем.")
        return

    ip_required = plugin.get("ip_required", False)
    vhost_required = plugin.get("vhost_required", False)

    if ip_required and not TARGET_IP:
        logging.info(f"{name} требует IP, но он не указан. Пропускаем.")
        return
    if vhost_required and not TARGET_DOMAIN:
        logging.info(f"{name} требует домен, но он не указан. Пропускаем.")
        return

    TARGET = TARGET_IP if ip_required else TARGET_DOMAIN

    if parser_type == "xml" and os.path.exists(output_path):
        logging.info(f"Удаляем старый XML: {output_path}")
        os.remove(output_path)

    success = await install_plugin(plugin)
    if not success:
        return

    level = plugin.get("level", "easy")
    level_args = plugin.get("levels", {}).get(level, {}).get("args", "")

    command_template = plugin.get("command", "")
    command = command_template.replace("{args}", level_args).replace("{target}", TARGET)
    if "{stdout}" in command:
        command = command.replace("{stdout}", output_path)

    try:
        if parser_type == "python" or not command_template:
            plugin_path = os.path.join(ROOT_DIR, "plugins", f"{name}.py")
            if not os.path.exists(plugin_path):
                logging.error(f"Файл плагина {plugin_path} не найден!")
                return

            spec = importlib.util.spec_from_file_location(name, plugin_path)
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)

            logging.info(f"Запуск Python-плагина {name}...")
            json_file = plugin_module.scan_with_dig()
            logging.info(f"{name} завершен. JSON сохранён в {json_file}")
            return

        logging.info(f"Запуск {name} (уровень: {level}): {command}")
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logging.error(f"{name} завершился с ошибкой: {stderr.decode().strip()}")
            return

        if parser_type in ["xml", "json"]:
            logging.info(f"{name} завершен. Результат сохранён в {output_path}")
            return

        try:
            result = json.loads(stdout.decode())
        except Exception:
            result = [
                {
                    "target": TARGET,
                    "type": name,
                    "severity": "info",
                    "data": stdout.decode().strip(),
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            ]

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        logging.info(f"{name} завершен. JSON сохранён в {output_path}")

    except Exception as e:
        logging.exception(f"Ошибка запуска {name}: {e}")


async def main():
    tasks = [run_tool(plugin) for plugin in PLUGINS if plugin.get("enabled")]
    await asyncio.gather(*tasks)

    for handler in logging.getLogger().handlers:
        handler.flush()


if __name__ == "__main__":
    asyncio.run(main())
