import asyncio
import json
import logging
import os
import shutil
import socket
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
LOG_PATH = os.path.join(ROOT_DIR, "logs", "app.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Читаем конфиг
with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

PLUGINS = CONFIG.get("plugins", [])
target_raw = CONFIG.get("scan_config", {}).get("target", "127.0.0.1")
try:
    TARGET = socket.gethostbyname(target_raw)
except socket.gaierror:
    TARGET = target_raw


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

        if process.returncode != 0:
            logging.error(
                f"Установка {name} не удалась на команде: {cmd}\n{stderr.decode().strip()}"
            )
            return False

    logging.info(f"{name} успешно установлен.")
    return True


async def run_tool(plugin):
    name = plugin["name"]
    command_template = plugin["command"]
    output_path = os.path.join(ROOT_DIR, plugin["output"])
    parser_type = plugin.get("parser", "json")  # 👈 Явно фиксируем

    if not plugin.get("enabled", False):
        logging.info(f"⏭ {name} отключен в конфиге. Пропускаем.")
        return

    # 🧹 Удаляем старый файл, если XML
    if parser_type == "xml" and os.path.exists(output_path):
        logging.info(f"Удаляем старый XML: {output_path}")
        os.remove(output_path)

    # Установка тулзы
    success = await install_plugin(plugin)
    if not success:
        return

    # Аргументы уровня
    level = plugin.get("level", "easy")
    level_args = plugin.get("levels", {}).get(level, {}).get("args", "")
    command = command_template.replace("{args}", level_args).replace("{target}", TARGET)

    # Обработка {stdout}
    if "{stdout}" in command:
        command = command.replace("{stdout}", output_path)

    logging.info(f"Запуск {name} (уровень: {level}): {command}")

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logging.error(f"{name} завершился с ошибкой: {stderr.decode().strip()}")
            return

        # ⛔ Не трогаем XML — он уже сохранён тулзой
        if parser_type == "xml":
            logging.info(f"{name} использует XML. Результат в {output_path}")
            return

        # JSON: stdout → file
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


if __name__ == "__main__":
    asyncio.run(main())
