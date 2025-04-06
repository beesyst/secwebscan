import importlib.util
import json
import logging
import os
import re
from datetime import datetime

import psycopg2

# Настройка логирования
LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"
)
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "app.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = "/config/config.json"
CATEGORY_KEYWORDS_PATH = os.path.join(ROOT_DIR, "config", "category_keywords.json")

with open(CONFIG_PATH, "r") as config_file:
    CONFIG = json.load(config_file)

DB_CONFIG = CONFIG["database"]
PLUGINS = CONFIG.get("plugins", [])

with open(CATEGORY_KEYWORDS_PATH, "r") as f:
    CATEGORY_KEYWORDS = json.load(f)


def connect_to_db():
    try:
        conn = psycopg2.connect(
            database=DB_CONFIG["POSTGRES_DB"],
            user=DB_CONFIG["POSTGRES_USER"],
            password=DB_CONFIG["POSTGRES_PASSWORD"],
            host=DB_CONFIG["POSTGRES_HOST"],
            port=DB_CONFIG["POSTGRES_PORT"],
        )
        logging.info("Успешное подключение к базе данных")
        return conn
    except psycopg2.Error as e:
        logging.error(f"Ошибка подключения к БД: {e}")
        exit(1)


def purge_results(cursor):
    logging.info("Очистка таблицы results...")
    try:
        cursor.execute("DELETE FROM results;")
        logging.info("Таблица results очищена.")
    except psycopg2.Error as e:
        logging.warning(f"Не удалось очистить results: {e}")


def load_plugin_parser(module_name):
    plugin_path = os.path.join("/plugins", f"{module_name}.py")
    if not os.path.exists(plugin_path):
        logging.error(f"Не найден файл парсера: {plugin_path}")
        return None

    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin


def detect_category(text):
    text = text.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if re.search(rf"\\b{re.escape(keyword)}\\b", text):
                return category
    return "General Info"


def process_module_results(cursor, module):
    if not module.get("enabled", False):
        return 0

    module_name = module["name"]
    output_path = f"/{module['output'].lstrip('/')}"

    if not os.path.exists(output_path):
        logging.warning(f"Результат {module_name} не найден: {output_path}")
        return 0

    plugin_parser = load_plugin_parser(module_name)
    if not plugin_parser or not hasattr(plugin_parser, "parse"):
        logging.error(f"Модуль {module_name} не содержит функцию parse")
        return 0

    try:
        results = plugin_parser.parse(output_path)
    except Exception as e:
        logging.error(f"Ошибка при обработке {module_name}: {e}")
        return 0

    table_name = "results"
    added = 0

    for item in results:
        try:
            timestamp = datetime.now()
            item["created_at"] = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            category_text = json.dumps(item.get("data", {}), ensure_ascii=False)
            detected_category = detect_category(category_text)

            cursor.execute(
                f"""
                INSERT INTO {table_name} (target, module, result_type, severity, data, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    item.get("target", "unknown"),
                    module_name,
                    detected_category,
                    item.get("severity", "info"),
                    category_text,
                    timestamp,
                ),
            )
            added += 1
        except psycopg2.Error as e:
            logging.warning(f"Ошибка вставки в {table_name}: {e}")
            continue

    logging.info(f"Добавлено {added} записей в {table_name}")
    return added


def collect():
    connection = connect_to_db()
    cursor = connection.cursor()

    purge_results(cursor)

    total_added = 0
    for module in PLUGINS:
        total_added += process_module_results(cursor, module)

    connection.commit()
    cursor.close()
    connection.close()

    logging.info(f"Завершено. Всего добавлено записей: {total_added}")


if __name__ == "__main__":
    collect()
