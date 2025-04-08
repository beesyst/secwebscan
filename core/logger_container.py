import logging
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
CONTAINER_LOG_PATH = os.path.join(LOGS_DIR, "container.log")

os.makedirs(LOGS_DIR, exist_ok=True)


def clear_container_log_if_needed(config: dict):
    """
    Эта функция вызывается из host-кода (например, start.py)
    до запуска контейнера.
    """
    clear_logs = config.get("scan_config", {}).get("clear_logs", False)
    if clear_logs:
        try:
            with open(CONTAINER_LOG_PATH, "w", encoding="utf-8") as f:
                f.truncate(0)
            print("🧹 container.log очищен (до старта контейнера)")
        except Exception as e:
            print(f"❌ Не удалось очистить container.log: {e}")


def setup_container_logger():
    """
    Этот код вызывается уже ВНУТРИ контейнера.
    Он не пытается очищать файл, а просто пишет в него.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()

    handler = logging.FileHandler(CONTAINER_LOG_PATH, mode="a", encoding="utf-8")
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
