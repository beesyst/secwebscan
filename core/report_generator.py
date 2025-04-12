import argparse
import json
import logging
import os
from collections import OrderedDict, defaultdict
from datetime import datetime

import psycopg2
from jinja2 import Environment, FileSystemLoader
from logger_container import setup_container_logger
from rich.console import Console
from rich.table import Table
from weasyprint import HTML

setup_container_logger()

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = "/templates"
OUTPUT_DIR = os.path.join(ROOT_DIR, "reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

CONFIG_PATH = "/config/config.json"
CATEGORY_KEYWORDS_PATH = os.path.join(ROOT_DIR, "config", "category_keywords.json")

with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

DB_CONFIG = CONFIG["database"]
PLUGINS = CONFIG.get("plugins", [])


def connect_to_db():
    return psycopg2.connect(
        database=DB_CONFIG["POSTGRES_DB"],
        user=DB_CONFIG["POSTGRES_USER"],
        password=DB_CONFIG["POSTGRES_PASSWORD"],
        host=DB_CONFIG["POSTGRES_HOST"],
        port=DB_CONFIG["POSTGRES_PORT"],
    )


def categorize_results(entries):
    plugin_categories = {
        plugin["name"]: plugin.get("category", "General Info") for plugin in PLUGINS
    }

    structured = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    meta_inserted = set()

    for entry in entries:
        target = entry["target"]
        module = entry.get("module")
        category = plugin_categories.get(module, "General Info")

        if target not in meta_inserted:
            structured[target]["__meta__"] = {
                "created_at": entry.get("created_at", "Unknown"),
                "mac": entry.get("mac", "-"),
            }
            meta_inserted.add(target)

        structured[target][category][module].append(entry)

    return structured


def sort_categories(structured):
    priority = {
        "Network Security": 0,
        "Application Security": 1,
        "DNS Health": 2,
        "Vulnerability Scan": 3,
        "Web Catalog & Crawl": 4,
        "OSINT / Metadata": 5,
        "Database Security": 6,
        "Cloud & API Exposure": 7,
        "General Info": 99,
    }

    sorted_targets = OrderedDict()
    for target, categories in structured.items():
        sorted_cats = OrderedDict()

        if "__meta__" in categories:
            sorted_cats["__meta__"] = categories["__meta__"]

        other_cats = {k: v for k, v in categories.items() if k != "__meta__"}
        for k in sorted(other_cats, key=lambda x: priority.get(x, 50)):
            sorted_cats[k] = other_cats[k]

        sorted_targets[target] = sorted_cats
    return sorted_targets


def load_and_categorize_results():
    raw_entries = []
    conn = connect_to_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT target, category, data, created_at, module FROM results ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()

        for row in rows:
            target, category, data, created_at, module = row

            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass

            raw_entries.append(
                {
                    "target": target,
                    "category": category,
                    "data": data,
                    "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "module": module,
                }
            )

    except Exception as e:
        logging.error(f"Ошибка при загрузке из results: {e}")

    cursor.close()
    conn.close()

    return categorize_results(raw_entries)


def render_html(results, output_path):
    logging.info(f"Поиск шаблона в: {TEMPLATES_DIR}")
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        logging.error(f"Ошибка загрузки шаблона: {e}")
        raise

    theme = CONFIG.get("scan_config", {}).get("report_theme", "light")

    rendered = template.render(
        structured_results=results,
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_theme=theme,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    logging.info(f"HTML-отчет создан: {output_path}")


def generate_pdf(html_path, pdf_path):
    HTML(html_path).write_pdf(pdf_path)
    logging.info(f"PDF-отчет создан: {pdf_path}")


import importlib


def show_in_terminal(results):
    console = Console(width=300)

    for target, categories in results.items():
        for category, sections in categories.items():
            for subcat, entries in sections.items():
                if subcat == "__meta__" or not isinstance(entries, list):
                    continue

                for entry in entries:
                    data = entry.get("data")
                    module = entry.get("module")

                    if isinstance(data, list) and all(
                        isinstance(d, dict) for d in data
                    ):
                        # Попробуем получить порядок колонок из plugins/{module}.py
                        column_order = None
                        try:
                            plugin_module = importlib.import_module(f"plugins.{module}")
                            if hasattr(plugin_module, "get_column_order"):
                                column_order = plugin_module.get_column_order()
                        except Exception:
                            pass

                        # Вычисляем уникальные ключи
                        all_keys = [
                            k
                            for d in data
                            for k in d.keys()
                            if k not in ["severity", "created_at", "module"]
                        ]
                        keys = (
                            [k for k in column_order if k in all_keys]
                            if column_order
                            else list(dict.fromkeys(all_keys))
                        )

                        table = Table(
                            title=f"[bold blue]{target} — {category} / {module}",
                            show_lines=True,
                        )
                        for k in keys:
                            table.add_column(
                                k.replace("_", " ").title(),
                                overflow="fold",
                                max_width=100,
                            )
                        for d in data:
                            table.add_row(*[str(d.get(k, "")) for k in keys])
                        console.print(table)

                    else:
                        table = Table(
                            title=f"[bold blue]{target} — {category} / {module}"
                        )
                        table.add_column("Data", overflow="fold")
                        table.add_row(json.dumps(data, ensure_ascii=False)[:1000])
                        console.print(table)


def main(format=None, timestamp=None):
    results = sort_categories(load_and_categorize_results())
    if not timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    clear_reports = CONFIG.get("scan_config", {}).get("clear_reports", False)
    if clear_reports:
        logging.info("Очистка папки reports перед генерацией отчёта...")
        for filename in os.listdir(OUTPUT_DIR):
            file_path = os.path.join(OUTPUT_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                logging.warning(f"Не удалось удалить файл {filename}: {e}")

    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    if format:
        formats = [format]

    if "terminal" in formats:
        show_in_terminal(results)

    if "html" in formats:
        logging.info("Проверка доступности шаблона...")
        logging.info(f"TEMPLATES_DIR = {TEMPLATES_DIR}")

        if not os.path.exists(TEMPLATES_DIR):
            logging.error("Папка шаблонов не найдена!")
            return

        try:
            files = os.listdir(TEMPLATES_DIR)
            logging.info(f"Файлы в шаблоне: {files}")
            if "report.html.j2" not in files:
                logging.error("Файл report.html.j2 не найден в шаблонах!")
                return
        except Exception as e:
            logging.error(f"Ошибка при чтении шаблонов: {e}")
            return

        html_output = os.path.join(OUTPUT_DIR, f"report_{timestamp}.html")
        render_html(results, html_output)

        if "pdf" in formats:
            pdf_output = os.path.join(OUTPUT_DIR, f"report_{timestamp}.pdf")
            generate_pdf(html_output, pdf_output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", help="Single format for backward compatibility")
    parser.add_argument("--timestamp", help="Timestamp to use in output filename")
    args = parser.parse_args()
    main(args.format, args.timestamp)
