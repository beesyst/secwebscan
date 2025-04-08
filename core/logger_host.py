import logging
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

HOST_LOG_PATH = os.path.join(LOGS_DIR, "host.log")


def setup_host_logger(config: dict):
    clear_logs = config.get("scan_config", {}).get("clear_logs", False)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()

    if clear_logs and os.path.exists(HOST_LOG_PATH):
        try:
            os.remove(HOST_LOG_PATH)
        except Exception as e:
            print(f"❌ Не удалось удалить host.log: {e}")

    handler = logging.FileHandler(HOST_LOG_PATH, mode="a", encoding="utf-8")
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
