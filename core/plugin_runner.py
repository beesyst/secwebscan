import os
import sys

sys.path.insert(0, "/")

import asyncio
import importlib.util
import json
import logging
import shutil

from core.logger_container import setup_container_logger

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
PLUGINS_DIR = os.path.join(ROOT_DIR, "plugins")

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

setup_container_logger()

PLUGINS = CONFIG.get("plugins", [])
SCAN_CONFIG = CONFIG.get("scan_config", {})
TARGET_IP = SCAN_CONFIG.get("target_ip")
TARGET_DOMAIN = SCAN_CONFIG.get("target_domain")

TEMP_FILES_PATH = os.getenv("TEMP_FILES_PATH")
generated_temp_paths = []

if not TARGET_IP and not TARGET_DOMAIN:
    raise ValueError(
        "Не указан ни target_ip, ни target_domain в конфиге. Укажите хотя бы один."
    )

if not TEMP_FILES_PATH:
    logging.critical("Переменная TEMP_FILES_PATH не установлена в окружении!")
    exit(1)


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

    ip_required = plugin.get("ip_required", False)
    vhost_required = plugin.get("vhost_required", False)

    if ip_required and not TARGET_IP:
        logging.info(f"{name} требует IP, но он не указан. Пропускаем.")
        return
    if vhost_required and not TARGET_DOMAIN:
        logging.info(f"{name} требует домен, но он не указан. Пропускаем.")
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
            temp_paths = loaded_plugin.scan(plugin, CONFIG, debug=False)

            if isinstance(temp_paths, list):
                generated_temp_paths.extend(temp_paths)
            elif isinstance(temp_paths, str):
                generated_temp_paths.append(temp_paths)

            logging.info(f"Плагин {name} успешно завершил работу.")
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
    paths = asyncio.run(main())

    for path in paths:
        print(f"🔹 Создан файл: {path}")

    try:
        with open(TEMP_FILES_PATH, "w", encoding="utf-8") as f:
            json.dump(paths, f, ensure_ascii=False)
        print(f"✅ Сохранены пути временных файлов: {TEMP_FILES_PATH}")
        logging.info(f"Сохранены пути временных файлов: {TEMP_FILES_PATH}")
    except Exception as e:
        print(f"❌ Ошибка записи TEMP_FILES_PATH: {e}")
        logging.error(f"Ошибка записи TEMP_FILES_PATH: {e}")
        exit(1)
