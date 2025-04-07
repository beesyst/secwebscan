import argparse
import importlib.util
import json
import os
from collections import OrderedDict, defaultdict
from datetime import datetime

import psycopg2
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.table import Table
from weasyprint import HTML

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
        "General Info": 99,
    }

    sorted_targets = OrderedDict()
    for target, categories in structured.items():
        sorted_cats = OrderedDict()

        # __meta__ всегда первым
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
            "SELECT target, category, severity, data, created_at, module FROM results ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()

        for row in rows:
            target, category, severity, data, created_at, module = row

            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass

            summary = ""
            plugin_path = os.path.join("/plugins", f"{module}.py")
            if os.path.exists(plugin_path):
                try:
                    import importlib.util

                    spec = importlib.util.spec_from_file_location(module, plugin_path)
                    plugin = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(plugin)

                    if hasattr(plugin, "get_summary"):
                        summary = plugin.get_summary(data)
                    else:
                        summary = str(data)[:80]
                except Exception as e:
                    summary = f"[Ошибка summary: {e}]"
            else:
                summary = str(data)[:80]

            raw_entries.append(
                {
                    "target": target,
                    "category": category,
                    "severity": severity,
                    "data": data,
                    "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "module": module,
                    "summary": summary,
                }
            )

    except Exception as e:
        print(f"[!] Ошибка при загрузке из results: {e}")

    cursor.close()
    conn.close()

    return categorize_results(raw_entries)


def render_html(results, output_path):
    print("📂 Поиск шаблона в:", TEMPLATES_DIR)
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        print("❌ Ошибка загрузки шаблона:", e)
        raise

    rendered = template.render(
        structured_results=results,
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"✅ HTML-отчёт создан: {output_path}")


def generate_pdf(html_path, pdf_path):
    HTML(html_path).write_pdf(pdf_path)
    print(f"✅ PDF-отчёт создан: {pdf_path}")


def show_in_terminal(results):
    console = Console()
    for target, categories in results.items():
        for category, sections in categories.items():
            for subcat, entries in sections.items():
                if subcat == "__meta__" or not isinstance(entries, list):
                    continue
                table = Table(title=f"[bold blue]{target} — {category} / {subcat}")
                table.add_column("Severity")
                table.add_column("Time")
                table.add_column("Summary", overflow="fold")

                for entry in entries:
                    module = entry.get("module")
                    data = entry.get("data")
                    summary = ""

                    # Загружаем плагин
                    plugin_path = os.path.join("/plugins", f"{module}.py")
                    if os.path.exists(plugin_path):
                        spec = importlib.util.spec_from_file_location(
                            module, plugin_path
                        )
                        plugin = importlib.util.module_from_spec(spec)
                        try:
                            spec.loader.exec_module(plugin)
                            if hasattr(plugin, "get_summary"):
                                summary = plugin.get_summary(data)
                            else:
                                summary = json.dumps(data)[:100]
                        except Exception as e:
                            summary = f"[Ошибка get_summary: {e}]"
                    else:
                        summary = str(data)[:100]

                    table.add_row(
                        entry.get("severity", "-"),
                        entry.get("created_at", "-"),
                        summary,
                    )

                console.print(table)


def main(format=None, timestamp=None):
    results = sort_categories(load_and_categorize_results())
    if not timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    if format:
        formats = [format]

    if "terminal" in formats:
        show_in_terminal(results)

    if "html" in formats:
        print("🔍 Проверка доступности шаблона...")
        print("TEMPLATES_DIR =", TEMPLATES_DIR)

        if not os.path.exists(TEMPLATES_DIR):
            print("❌ Папка шаблонов не найдена!")
            return

        try:
            files = os.listdir(TEMPLATES_DIR)
            print("📂 Файлы в шаблоне:", files)
            if "report.html.j2" not in files:
                print("❌ Файл report.html.j2 не найден в шаблонах!")
                return
        except Exception as e:
            print("❌ Ошибка при чтении шаблонов:", e)
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
