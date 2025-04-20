import json
import logging
import os
import subprocess
import sys
import threading
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


def spinner(prefix: str, stop_event: threading.Event):
    symbols = ["⠁", "⠂", "⠄", "⠂"]
    i = 0
    try:
        sys.stdout.write("\033[?25l")
        while not stop_event.is_set():
            sys.stdout.write(f"\r{prefix} {symbols[i % len(symbols)]}")
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)
    finally:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


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
        print(f"❌ Ошибка выполнения: {command}")
        logging.error(f"Ошибка выполнения команды: {command}")
        return False
    return True


def run_command_with_spinner(command, prefix, cwd=None, hide_output=True):
    # logging.info(f"{prefix}...")
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=(prefix, stop_event))
    spinner_thread.start()

    result = subprocess.run(
        command,
        shell=True,
        cwd=cwd,
        stdout=subprocess.DEVNULL if hide_output else None,
        stderr=subprocess.DEVNULL if hide_output else None,
    )

    stop_event.set()
    spinner_thread.join()

    if result.returncode != 0:
        print(f"❌ Ошибка выполнения: {command}")
        logging.error(f"Ошибка выполнения команды: {command}")
        return False
    return True


def check_docker_installed():
    try:
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.DEVNULL)
        logging.info("Docker установлен.")
    except subprocess.CalledProcessError:
        print("🚨 Ошибка: Docker не установлен.")
        logging.critical("Docker не установлен!")
        exit(1)


def clean_docker_environment():
    result = subprocess.run(
        ["docker", "network", "ls", "-q", "--filter", f"name={NETWORK_NAME}"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if not result.stdout.strip():
        print(f"🌐 Сеть {NETWORK_NAME} не найдена. Создаю...")
        logging.info(f"Сеть {NETWORK_NAME} не найдена. Создание...")
        run_command_with_spinner(
            f"docker network create {NETWORK_NAME}", "⏳ Создание сети"
        )
        print(f"\r✅ Сеть {NETWORK_NAME} установлена.")
        logging.info(f"Создана сеть Docker: {NETWORK_NAME}")
    else:
        print(f"✅ Сеть {NETWORK_NAME} найдена.")
        logging.info(f"Сеть {NETWORK_NAME} уже существует.")


def start_postgres():
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name={DB_CONTAINER}"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout.strip():
        print("✅ PostgreSQL запущен.")
        logging.info("PostgreSQL уже работает.")
        return

    print("🗄️ PostgreSQL не найден. Запускаю контейнер...")
    logging.info("Контейнер PostgreSQL не найден. Запуск...")
    run_command_with_spinner(
        "docker compose -f db/compose.yaml up --build -d",
        "⏳ Запуск PostgreSQL...",
        cwd=ROOT_DIR,
    )

    time.sleep(1)
    for _ in range(30):
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
            print("\r✅ PostgreSQL готов к работе!")
            logging.info("PostgreSQL запущен и готов к работе.")
            return
        time.sleep(1)

    print("\n❌ Ошибка: PostgreSQL не запустился.")
    logging.critical("PostgreSQL не стартовал вовремя!")
    exit(1)


def ensure_secwebscan_base_image():
    result = subprocess.run(
        ["docker", "images", "-q", "secwebscan-base"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if not result.stdout.strip():
        print("📦 Образ secwebscan-base не найден. Начинаю сборку...")
        logging.info("Образ secwebscan-base не найден. Запуск сборки...")
        success = run_command_with_spinner(
            "docker build -t secwebscan-base -f docker/Dockerfile.base .",
            "⏳ Сборка образа",
            cwd=ROOT_DIR,
            hide_output=True,
        )
        if not success:
            print("❌ Сборка образа завершилась с ошибкой.")
            logging.critical("Сборка secwebscan-base не удалась.")
            exit(1)
        print("✅ Образ secwebscan-base собран успешно.")
        logging.info("Сборка secwebscan-base завершена успешно.")
    else:
        print("✅ Образ secwebscan-base существует.")
        logging.info("Образ secwebscan-base найден.")


def start_secwebscan_container():
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=secwebscan_base"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout.strip():
        print("✅ Контейнер secwebscan_base уже работает.")
        logging.info("Контейнер secwebscan_base уже запущен.")
        return

    result_all = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=secwebscan_base"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result_all.stdout.strip():
        print("🗑️ Обнаружен остановленный контейнер secwebscan_base. Удаляем...")
        logging.info("Удаление остановленного контейнера secwebscan_base.")
        subprocess.run(["docker", "rm", "-f", "secwebscan_base"])

    print("📦 Контейнер secwebscan-base не найден. Запускаю...")
    logging.info("Запуск контейнера secwebscan_base...")

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
        "-v",
        "/etc/timezone:/etc/timezone:ro",
        "-v",
        "/etc/localtime:/etc/localtime:ro",
    ]

    success = run_command_with_spinner(
        f"docker run -d --name secwebscan_base --network {NETWORK_NAME} "
        + " ".join(volumes)
        + " secwebscan-base tail -f /dev/null",
        prefix="⏳ Запуск контейнера secwebscan_base...",
        cwd=ROOT_DIR,
    )

    if success:
        print("✅ Контейнер secwebscan_base готов.")
        logging.info("Контейнер secwebscan_base запущен успешно.")


def run_plugins():
    print("🔧 Запуск всех плагинов асинхронно...")
    logging.info("Запуск всех плагинов через plugin_runner.py")
    run_command_with_spinner(
        "docker exec secwebscan_base python3 /core/plugin_runner.py",
        "⏳ Плагины выполняются...",
    )


def run_collector():
    print("📥 Сбор результатов в БД...")
    logging.info("Сбор результатов: запуск collector.py внутри контейнера")
    run_command(
        "docker exec secwebscan_base python3 /core/collector.py", hide_output=False
    )


def generate_reports():
    print("📄 Генерация отчетов...")
    logging.info("Генерация отчётов начата.")
    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    open_report = CONFIG.get("scan_config", {}).get("open_report", False)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_report_name = f"report_{timestamp}.html"
    html_report_path = os.path.join(ROOT_DIR, "reports", html_report_name)

    for fmt in formats:
        if fmt not in ["html", "pdf", "txt", "terminal"]:
            print(f"⚠️ Формат {fmt} не поддерживается. Пропускаем.")
            logging.warning(f"Неподдерживаемый формат отчета: {fmt}")
            continue

        print(f"📝 Генерация {fmt.upper()}...")
        logging.info(f"Генерация отчета в формате {fmt.upper()}...")
        success = run_command(
            f"docker exec secwebscan_base python3 /core/report_generator.py --format {fmt} --timestamp {timestamp}",
            hide_output=False,
        )

        if success:
            print(f"✅ Отчет {fmt.upper()} готов.")
            logging.info(f"Отчет {fmt.upper()} сгенерирован успешно.")
        else:
            logging.error(f"Ошибка при генерации отчета в формате {fmt.upper()}.")
            continue

        if open_report and fmt == "html" and os.path.exists(html_report_path):
            try:
                print(f"🌐 Открываем HTML-отчет в браузере: {html_report_path}")
                logging.info(f"Открытие HTML-отчета: {html_report_path}")
                subprocess.Popen(
                    ["xdg-open", html_report_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                logging.warning(f"Не удалось открыть HTML-отчет: {e}")


def post_scan_chown():
    try:
        user_id = os.getuid()
        group_id = os.getgid()
        run_command(
            f"docker exec secwebscan_base chown -R {user_id}:{group_id} /reports",
            hide_output=False,
        )
        print(f"✅ Права на /reports обновлены: {user_id}:{group_id}")
        logging.info(f"Изменены права доступа /reports на {user_id}:{group_id}")
    except Exception as e:
        print(f"⚠️ Ошибка при попытке сменить владельца отчётов: {e}")
        logging.warning(f"Не удалось изменить владельца отчётов: {e}")


def main():
    print("🚀 Запуск SecWebScan...")
    logging.info("==== SecWebScan запуск начат ====")
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
    logging.info("==== SecWebScan завершён успешно ====")


if __name__ == "__main__":
    main()
