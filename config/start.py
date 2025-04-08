import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
LOGS_PATH = os.path.join(ROOT_DIR, "logs", "host.log")

with open(CONFIG_PATH, "r") as config_file:
    CONFIG = json.load(config_file)

sys.path.insert(0, ROOT_DIR)
from core.logger_container import clear_container_log_if_needed
from core.logger_host import setup_host_logger

setup_host_logger(CONFIG)
clear_container_log_if_needed(CONFIG)

DB_CONTAINER = CONFIG["database"]["container_name"]
NETWORK_NAME = CONFIG["docker_network"]


def run_command(command, cwd=None, hide_output=True):
    logging.info(f"Выполнение команды: {command}")
    result = subprocess.run(
        command,
        shell=True,
        cwd=cwd,
        stdout=subprocess.DEVNULL if hide_output else None,
        stderr=subprocess.DEVNULL if hide_output else None,
    )
    if result.returncode != 0:
        logging.error(f"Ошибка выполнения команды: {command}")
        print(f"❌ Ошибка выполнения: {command}")
        return False
    return True


def check_docker_installed():
    try:
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        logging.critical("Docker не установлен!")
        print("🚨 Ошибка: Docker не установлен.")
        exit(1)


def clean_docker_environment():
    print("🖧 Проверка сети Docker...")
    result = subprocess.run(
        ["docker", "network", "ls", "-q", "--filter", f"name={NETWORK_NAME}"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if not result.stdout.strip():
        print(f"🌐 Создание сети {NETWORK_NAME}...")
        logging.info(f"Создание сети Docker: {NETWORK_NAME}")
        subprocess.run(
            ["docker", "network", "create", NETWORK_NAME],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        print(f"✅ Сеть {NETWORK_NAME} уже существует. Пропускаем создание.")
        logging.info(f"Сеть {NETWORK_NAME} уже существует.")


def start_postgres():
    print("🐘 Запуск PostgreSQL...")
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name={DB_CONTAINER}"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout.strip():
        print("✅ PostgreSQL уже запущен. Пропускаем создание.")
        logging.info("PostgreSQL уже работает.")
        return

    run_command("docker compose -f db/compose.yaml up --build -d", cwd=ROOT_DIR)

    print("⏳ Ожидание готовности PostgreSQL...")
    for attempt in range(30):
        print(f"🔄 Проверка готовности PostgreSQL (попытка {attempt + 1}/30)...")
        result = subprocess.run(
            [
                "docker",
                "exec",
                DB_CONTAINER,
                "pg_isready",
                "-U",
                CONFIG["database"]["POSTGRES_USER"],
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            print("✅ PostgreSQL готов к работе!")
            logging.info("PostgreSQL запущен и готов к работе.")
            return
        time.sleep(2)

    print("❌ Ошибка: PostgreSQL не запустился.")
    logging.critical("PostgreSQL не стартовал вовремя!")
    exit(1)


def ensure_secwebscan_base_image():
    result = subprocess.run(
        ["docker", "images", "-q", "secwebscan-base"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if not result.stdout.strip():
        print("📦 Образ secwebscan-base не найден. Собираем...")
        logging.info("Образ secwebscan-base не найден. Начинаем сборку...")
        build_cmd = "docker build -t secwebscan-base -f docker/Dockerfile.base ."
        success = run_command(build_cmd, cwd=ROOT_DIR)
        if not success:
            logging.critical("Не удалось собрать образ secwebscan-base.")
            print("❌ Критическая ошибка: сборка образа не удалась.")
            exit(1)
    else:
        logging.info("Образ secwebscan-base найден.")


def start_secwebscan_container():
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=secwebscan_base"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout.strip():
        print("✅ Контейнер secwebscan_base уже работает. Пропускаем.")
        return

    result_all = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=secwebscan_base"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result_all.stdout.strip():
        print("🗑️ Обнаружен остановленный контейнер secwebscan_base. Удаляем...")
        subprocess.run(["docker", "rm", "-f", "secwebscan_base"])

    print("🚀 Запуск контейнера secwebscan_base...")
    volumes = [
        "-v",
        f"{os.path.join(ROOT_DIR, 'core')}:/core",
        "-v",
        f"{os.path.join(ROOT_DIR, 'results')}:/results",
        "-v",
        f"{os.path.join(ROOT_DIR, 'logs', 'container.log')}:/logs/container.log",
        "-v",
        f"{os.path.join(ROOT_DIR, 'config')}:/config",
        "-v",
        f"{os.path.join(ROOT_DIR, 'templates')}:/templates",
        "-v",
        f"{os.path.join(ROOT_DIR, 'reports')}:/reports",
        "-v",
        f"{os.path.join(ROOT_DIR, 'plugins')}:/plugins",
    ]

    run_command(
        f"docker run -d --name secwebscan_base --network {NETWORK_NAME} "
        + " ".join(volumes)
        + " secwebscan-base tail -f /dev/null",
        cwd=ROOT_DIR,
    )


def run_plugins():
    print("🔧 Запуск всех плагинов асинхронно...")
    logging.info("Запуск plugin_runner.py...")
    run_command(
        "docker exec secwebscan_base python3 /core/plugin_runner.py", hide_output=False
    )


def run_collector():
    print("📥 Сбор результатов в БД...")
    logging.info("Запуск collector.py внутри контейнера...")
    run_command(
        "docker exec secwebscan_base python3 /core/collector.py", hide_output=False
    )


def generate_reports():
    print("📄 Генерация отчетов...")
    logging.info("Генерация отчётов...")

    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    open_report = CONFIG.get("scan_config", {}).get("open_report", False)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_report_name = f"report_{timestamp}.html"
    html_report_path = os.path.join(ROOT_DIR, "reports", html_report_name)

    for fmt in formats:
        if fmt not in ["html", "pdf", "txt", "terminal"]:
            logging.warning(f"Неподдерживаемый формат отчета: {fmt}")
            print(f"⚠️ Формат {fmt} не поддерживается. Пропускаем.")
            continue

        print(f"📝 Генерация {fmt.upper()}...")
        logging.info(f"Начинаем генерацию отчета в формате {fmt.upper()}")

        success = run_command(
            f"docker exec secwebscan_base python3 /core/report_generator.py --format {fmt} --timestamp {timestamp}",
            hide_output=False,
        )

        if success:
            logging.info(f"Отчет в формате {fmt.upper()} успешно сгенерирован.")
            print(f"✅ Отчет {fmt.upper()} готов.")
        else:
            logging.error(f"Не удалось сгенерировать отчет в формате {fmt.upper()}.")
            continue

        if open_report and fmt == "html":
            if os.path.exists(html_report_path):
                try:
                    print(f"🌐 Открываем HTML-отчёт в браузере: {html_report_path}")
                    logging.info(f"Открытие HTML-отчета: {html_report_path}")
                    subprocess.Popen(
                        ["xdg-open", html_report_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception as e:
                    logging.warning(f"Не удалось открыть HTML-отчет: {e}")
            else:
                logging.warning(f"HTML-отчет не найден: {html_report_path}")


def post_scan_chown():
    try:
        user_id = os.getuid()
        group_id = os.getgid()
        run_command(
            f"docker exec secwebscan_base chown -R {user_id}:{group_id} /reports",
            hide_output=False,
        )
        logging.info(
            f"Права доступа к /reports обновлены внутри контейнера на {user_id}:{group_id}"
        )
        print(f"✅ Права на /reports обновлены: {user_id}:{group_id}")
    except Exception as e:
        logging.warning(f"Не удалось изменить владельца отчётов внутри контейнера: {e}")
        print(f"⚠️ Ошибка при попытке сменить владельца отчётов: {e}")


def main():
    check_docker_installed()
    clean_docker_environment()
    start_postgres()
    ensure_secwebscan_base_image()
    start_secwebscan_container()
    run_plugins()
    run_collector()
    generate_reports()
    post_scan_chown()
    print("✅ SecWebScan завершил выполнение!")
    logging.info("SecWebScan завершил выполнение!")


if __name__ == "__main__":
    main()
