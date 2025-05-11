import os
import sys

sys.path.insert(0, "/")

import argparse
import asyncio
import importlib.util
import json
import logging
import shutil
import time

from core.logger_container import setup_container_logger
from core.logger_plugin import clear_plugin_logs_if_needed

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
PLUGINS_DIR = os.path.join(ROOT_DIR, "plugins")

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

setup_container_logger()
clear_plugin_logs_if_needed(CONFIG)
PLUGINS = CONFIG.get("plugins", [])
SCAN_CONFIG = CONFIG.get("scan_config", {})
TARGET_IP = SCAN_CONFIG.get("target_ip")
TARGET_DOMAIN = SCAN_CONFIG.get("target_domain")

generated_temp_paths = []
duration_map = {}

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

        logging.info(f"Выполняется команда: {cmd}")
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logging.error(
                f"Установка {name} не удалась на команде: {cmd}\n{stderr.decode().strip()}"
            )
            return False

    logging.info(f"{name} успешно установлен.")
    return True


async def run_plugin(plugin):
    name = plugin["name"]

    if not plugin.get("enabled", False):
        logging.info(f"Плагин {name} отключен в конфиге. Пропускаем.")
        return

    success = await install_plugin(plugin)
    if not success:
        return

    plugin_path = os.path.join(PLUGINS_DIR, f"{name}.py")
    if not os.path.exists(plugin_path):
        logging.error(f"Файл плагина {plugin_path} не найден!")
        return

    try:
        spec = importlib.util.spec_from_file_location(name, plugin_path)
        loaded_plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded_plugin)

        if hasattr(loaded_plugin, "scan"):
            logging.info(f"Запуск функции scan() из плагина {name}...")
            start = time.time()
            temp_paths = await loaded_plugin.scan(CONFIG)
            duration_map[name] = round(time.time() - start, 2)
            logging.info(
                f"Плагин {name} успешно завершил работу за {duration_map[name]} сек."
            )

            if isinstance(temp_paths, list):
                for path in temp_paths:
                    if isinstance(path, str):
                        generated_temp_paths.append({"plugin": name, "path": path})
                    elif isinstance(
                        path, dict
                    ):  # защита, если плагин уже вернул словари
                        generated_temp_paths.append(path)
            elif isinstance(temp_paths, str):
                generated_temp_paths.append({"plugin": name, "path": temp_paths})

        else:
            logging.error(f"Плагин {name} не содержит функцию scan(). Пропускаем.")
    except Exception as e:
        logging.exception(f"Ошибка при запуске плагина {name}: {e}")


async def main():
    tasks = [run_plugin(plugin) for plugin in PLUGINS if plugin.get("enabled")]
    await asyncio.gather(*tasks)

    for handler in logging.getLogger().handlers:
        handler.flush()

    return generated_temp_paths


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        required=True,
        help="Путь для сохранения JSON-файла с результатами сканирования",
    )
    args = parser.parse_args()

    paths = asyncio.run(main())

    try:
        combined_data = {
            "paths": paths,
            "durations": [
                {"plugin": k, "duration": v} for k, v in duration_map.items()
            ],
        }

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=2)

        logging.info(f"Сохранены пути и duration-данные: {args.output}")

    except Exception as e:
        print(f"❌ Ошибка записи JSON: {e}")
        logging.error(f"Ошибка записи JSON-файлов: {e}")
        exit(1)
