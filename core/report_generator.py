import argparse
import json
import os
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


def load_results_from_db():
    results = {}
    conn = connect_to_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT target, result_type, severity, data, created_at FROM results ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()

        for row in rows:
            target, result_type, severity, data, created_at = row

            # print(f"[DEBUG] row: target={target}, type={result_type}, severity={severity}, created_at={created_at}, data={type(data)}")

            if result_type not in results:
                results[result_type] = []

            # Убедись, что data — это всегда JSON-совместимая структура
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass  # пусть остаётся строкой

            results[result_type].append(
                {
                    "target": target,
                    "type": result_type,
                    "severity": severity,
                    "data": data,
                    "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    except Exception as e:
        print(f"[!] Ошибка при загрузке из results: {e}")

    cursor.close()
    conn.close()
    return results


def render_html(results, output_path):
    print("📂 Поиск шаблона в:", TEMPLATES_DIR)
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        print("❌ Ошибка загрузки шаблона:", e)
        raise

    rendered = template.render(
        results=results, generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"✅ HTML-отчёт создан: {output_path}")


def generate_pdf(html_path, pdf_path):
    HTML(html_path).write_pdf(pdf_path)
    print(f"✅ PDF-отчёт создан: {pdf_path}")


def show_in_terminal(results: dict):
    console = Console()

    for module, entries in results.items():
        table = Table(title=f"[bold blue]{module.upper()} Results")

        table.add_column("Target")
        table.add_column("Type")
        table.add_column("Severity")
        table.add_column("Created At")
        table.add_column("Summary", overflow="fold")

        for entry in entries:
            data = entry.get("data")
            if isinstance(data, list):
                summary = ""
                for item in data:
                    if isinstance(item, dict):
                        summary += f"{item.get('port', '?')}/{item.get('protocol', '?')} {item.get('state', '?')} | "
                summary = summary.strip(" | ")
            else:
                summary = str(data)

            table.add_row(
                entry.get("target", "-"),
                entry.get("type", "-"),
                entry.get("severity", "-"),
                entry.get("created_at", "-"),
                summary[:120] + "..." if len(summary) > 120 else summary,
            )

        console.print(table)


def main(format=None, timestamp=None):
    results = load_results_from_db()
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
