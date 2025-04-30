import logging
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")


def get_plugin_log_path(plugin_name: str) -> str:
    """Возвращает путь к лог-файлу плагина."""
    return os.path.join(LOGS_DIR, f"{plugin_name}.log")


def setup_plugin_logger(plugin_name: str):
    logger = logging.getLogger(plugin_name)
    logger.setLevel(logging.INFO)

    log_path = os.path.join(LOGS_DIR, f"{plugin_name}.log")

    if logger.hasHandlers():
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()

    file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def clear_plugin_logs_if_needed(config: dict):
    clear_logs = config.get("scan_config", {}).get("clear_logs", False)
    if clear_logs and os.path.exists(LOGS_DIR):
        for file in os.listdir(LOGS_DIR):
            if file.endswith(".log") and file not in ("host.log", "container.log"):
                try:
                    with open(os.path.join(LOGS_DIR, file), "w", encoding="utf-8") as f:
                        f.truncate(0)
                except Exception as e:
                    print(f"❌ Не удалось очистить лог {file}: {e}")
